
/*
	$Id: roms.c,v 1.4 1998/03/04 02:13:12 offer Exp $

	Copyright (c) 1996-1998 Richard M. Offer

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

	
Author: offer@sgi.com
*/

#include <stdio.h>
#include <stdlib.h> 	/* for getenv() qsort() */
#include <regex.h>	/* POSIX regular expressions */
#include <unistd.h>	/* for getopt() (POSIX version)
				use <getopt.h> for GNU style long options */
#include <string.h>	/* for strtok() */
#include <dirent.h>
#include <time.h>

#include <pwd.h> /* for password access */
/* for SunOs */
#ifndef RAND_MAX
#define RAND_MAX (2147483647)
#endif

#define ADDRESSFILE ".addresses"
#define NAMEFILE ".fullname"

#define NewString(a) (a?strcpy((char *)malloc(strlen(a)+1),a):NULL)
#define NewStringPlusExtra(a,b) (a?strcpy((char *)malloc(strlen(a)+b+1),a):NULL)

typedef enum { Random, Sequential } OrderType;

typedef struct _dbentry {

	char	*name;
	regex_t	regex; /* name compiled into regex form for speed */
	char	*dir;
} dbEntry;

typedef struct _addressee {
	char	*name;
	dbEntry	*dbentry;
	int		best_match;
} Addressee;

int sortOnDirectory(const void *p1, const void *p2)
{

	Addressee	*a1=(Addressee *)p1;
	Addressee	*a2=(Addressee *)p2;

	return (strcmp( a1->dbentry->dir, a2->dbentry->dir));
}


int sortOnFilenames(const void *p1, const void *p2)
{

	char **s1 = (char **) p1;
	char **s2 = (char **) p2;
	return (strcmp(*s1, *s2));
}


int main(argc,argv)
int	argc;
char	**argv;
{

	FILE		*addressDB,*sig,*seq;
	DIR			*sigDir;
	struct dirent *entry;
	char		addressDBname[256];
	char		line[256],name[128],dir[128];
	char		errorbuf[256];
	char		*libdir,*address;
	char		**sigs;
	char		cmd_l_add[1024];
	dbEntry		*dbNames = NULL;
	Addressee	*addressees = NULL;
	regmatch_t 	patch[2];
	size_t		nmatch;
	int			c,i,j,ndbNames,naddressees,nsigs;
	int			err;
	OrderType 	indexType = Random;
	int 		lookup;
	int			returnName = 0;

/* for getopt() */
    extern char *optarg;
    extern int 	optind, opterr, optopt;


	if ( argc < 2 )  {
		fprintf(stderr,"No addresses on cmd-line\n");
		return 1;
	}

	libdir = getenv("ROMSDIR");

	if ( libdir == NULL ) 
		libdir = getenv("HOME");

/* parse the command line for arguments */

	opterr = 0; /* switch off getopt error reporting */

	while ( (c=getopt(argc,argv,"d:rsn")) != EOF ) { 

		switch (c) { 

			case 'd':
				libdir = optarg;
				break;

			case 'r':
				indexType = Random;
				break;

			case 's':
				indexType = Sequential;
				break;
				
			case 'n':
				returnName = 1;
				break;

		}

	}	
	
	cmd_l_add[0] = '\0';

	for (i=optind; i< argc; i++ ) 
		strcat(cmd_l_add,argv[i]);
	
	naddressees=0;
	address = strtok(cmd_l_add,",");

	addressees = (Addressee *) malloc(sizeof(Addressee));

	addressees[naddressees].name = cmd_l_add;
	addressees[naddressees].best_match = 0;
	addressees[naddressees].dbentry = NULL;
	naddressees++;

	if ( address != NULL ) { 

		while( (address=strtok(NULL,",")) != NULL ) {
	
			addressees = (Addressee *) realloc((char *) addressees, 
											(sizeof(Addressee)*(naddressees+1)));
			addressees[naddressees].name = NewString(address);
			addressees[naddressees].best_match = 0;
			addressees[naddressees].dbentry = NULL;
			naddressees++;
		}
	}


	sprintf(addressDBname,"%s/%s",libdir,ADDRESSFILE);

	addressDB = fopen(addressDBname,"r");

	if ( addressDB == NULL ) { 
		fprintf(stderr,"%s: Cannot open Address DataBase '%s'\n",
			argv[0],
			addressDBname);
		exit(1);
	}

/* load the database from the address file */

	ndbNames = 0;
	while ( fgets(line,255,addressDB) != NULL ) { 

		if ( sscanf(line,"%s %s",name,dir) != 2 ) 
			continue;
		
		if ( name[0] == '#' ) 
			continue;

		if ( dbNames == NULL ) 
			dbNames = (dbEntry *) malloc(sizeof(dbEntry));
		else
			dbNames = (dbEntry *) realloc((char *) dbNames,sizeof(dbEntry) * ( ndbNames+1));

/* compile name into reg-exp, compare as case-insensitive */
		if ( (err=regcomp(&(dbNames[ndbNames].regex),name,REG_ICASE | REG_EXTENDED)) != 0 )  {
			regerror(err,&(dbNames[ndbNames].regex),errorbuf,255);
			fprintf(stderr,"%s: %s\n",argv[0],errorbuf);
		}
		dbNames[ndbNames].dir = NewStringPlusExtra(libdir,strlen(dir)+1);
		strcat(dbNames[ndbNames].dir,"/");
		strcat(dbNames[ndbNames].dir,dir);

		dbNames[ndbNames].name = NewString(name);

		ndbNames++;
	}

	nmatch = 2;
	
	for (i=0; i<naddressees; i++ ) {


		for ( j=0; j < ndbNames; j++ ) {
			if ( regexec(&(dbNames[j].regex),
						 addressees[i].name,
						 nmatch,patch,0) == 0 ) {
				if ( (patch[0].rm_eo - patch[0].rm_so) > 
					  addressees[i].best_match ) {  

					addressees[i].dbentry = &dbNames[j];
					addressees[i].best_match = (patch[0].rm_eo - patch[0].rm_so); 


				}
			}	
		}
		if ( addressees[i].dbentry == NULL ) {
			fprintf(stderr,"cannot match '%s'\n",addressees[i].name);
			return 1;
		}
	}

	if ( naddressees > 1 ) 
		qsort((void *) addressees,
			naddressees,
        	sizeof(Addressee),
        	sortOnDirectory);
	


	if ( returnName == 1 ) {
		sprintf(addressDBname,
			"%s/%s",
			addressees[0].dbentry->dir,NAMEFILE);
	
		sig = fopen(addressDBname,"r");
		if ( sig == NULL ) {
			struct passwd *pw = getpwnam(getlogin());
			
			fprintf(stderr,"Using name '%s' from password file\n",pw->pw_name);
			fprintf(stdout,"%s\n",pw->pw_name);
			return 0;
		}
			
		fgets(line,255,sig);
		fputs(line,stdout);
		line[strlen(line) -1] = '\0';
		fprintf(stderr,"Using name '%s'\n",line);
		fclose(sig);
		
		return 0;
		
	}

	sigDir = opendir(addressees[0].dbentry->dir);


    if ( sigDir == NULL ) {
            fprintf(stderr,"opendir(%s) failed\n",addressees[0].dbentry->dir);
			return(3);
	}


    nsigs = 0;
    while( (entry = readdir(sigDir) ) != NULL ) {

		if ( entry->d_name[0] != '.' ) 
          	nsigs++;
    }


    sigs = (char **) malloc(sizeof(char *) * nsigs );

    rewinddir(sigDir);

    i=0;

    while( (entry = readdir(sigDir) ) != NULL ) {

/* remove all dot files */
		if ( entry->d_name[0] != '.' ) {
        	sigs[i] = NewString(entry->d_name);
          	i++;
		}
    }


	if ( indexType == Random ) { 

		srand( (int) ( time(NULL) % getpid())  );

		lookup = (int) ( (double) nsigs * rand() / (RAND_MAX + 1.0) ); 

	}
	else {

		qsort((void *) sigs,
			nsigs,
        	sizeof(char *),
        	sortOnFilenames);

		sprintf(addressDBname,
				"%s/.index",
				addressees[0].dbentry->dir);

		if ( (seq=fopen(addressDBname,"r")) != NULL ) {  
			fscanf(seq,"%d",&lookup);
			fclose(seq);
		}
		else
			lookup = 0;

		if ( (seq=fopen(addressDBname,"w")) != NULL ) {  
			if ( lookup == nsigs-1 )
				fprintf(seq,"%d",0); 
			else
				fprintf(seq,"%d",lookup+1); 
		}
		else
			fprintf(stderr,
					"cannot open '%s' for sequential mode.\n",
					addressDBname);

	}


	sprintf(addressDBname,
			"%s/%s",
			addressees[0].dbentry->dir,sigs[lookup]);

	sig = fopen(addressDBname,"r");
	
	if ( sig == NULL) { 
		fprintf(stderr,"cannot open '%s'\n",addressDBname);
		return(1);
	}
	else {
		fprintf(stderr,"using sig in '%s'\n",addressDBname);
	}
		

	while( fgets(line,255,sig) != NULL ) { 

		fputs(line,stdout);
	}

	fclose(sig);

	return(0);
}
