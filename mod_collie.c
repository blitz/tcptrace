/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998
 *	Ohio University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the
 * distribution, and (3) all advertising materials mentioning features
 * or use of this software display the following acknowledgment:
 * ``This product includes software developed by the Ohio University
 * Internetworking Research Laboratory.''  Neither the name of the
 * University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific
 * prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 */
static char const rcsid[] =
   "$Header$";

#ifdef LOAD_MODULE_COLLIE

#include "tcptrace.h"
#include "mod_collie.h"

/* this module was written as a favor for a friend, but serves as a */
/* useful little example of a quick hack... :-) */



/* additional info kept per connection */
struct conn_info {
    tcp_pair *ptp;
    struct conn_info *next;
};
static struct conn_info *connhead = NULL;


/* additional info kept per UDP pair */
struct uconn_info {
    udp_pair *pup;
    struct uconn_info *next;
};
static struct uconn_info *uconnhead = NULL;


/* locally-global info */
static char *collie_filename = NULL;
static Bool print_labels = TRUE;


/* local routines */
static struct conn_info *MakeConnRec(void);
static struct uconn_info *MakeUDPConnRec(void);
static char *collie_name(ipaddr ipaddress);
static char *collie_dots(ipaddr ipaddress);
static char *collie_time(struct timeval *ptime);
static char *collie_date(time_t timestamp);
static void ParseArgs(char *argstring);



/* Set it up */
int
collie_init(
    int argc,
    char *argv[])
{
    int i;
    int enable=0;
    char *args = NULL;

    for (i=1; i < argc; ++i) {
	if (!argv[i])
	    continue;  /* argument already taken by another module... */
	if (strncmp(argv[i],"-x",2) == 0) {
	    if (strncasecmp(argv[i]+2,"collie",sizeof("collie")-1) == 0) {
		/* I want to be called */
		args = argv[i]+(sizeof("-xcollie")-1);
		enable = 1;
		argv[i] = NULL;
	    }
	}
    }

    if (!enable)
	return(0);	/* don't call me again */

    /* parse any arguments for ME */
    ParseArgs(args);

    /* we don't want the normal output */
    printsuppress = TRUE;

    /* please also include UDP packets */
    do_udp = TRUE;

    return(1);	/* TRUE means call collie_read and collie_done later */
}



static struct conn_info *
MakeConnRec(void)
{
    struct conn_info *pci;

    pci = MallocZ(sizeof(struct conn_info));

    /* chain it in (at head of list) */
    pci->next = connhead;
    connhead = pci;

    return(pci);
}


static struct uconn_info *
MakeUDPConnRec(void)
{
    struct uconn_info *puci;

    puci = MallocZ(sizeof(struct uconn_info));

    /* chain it in (at head of list) */
    puci->next = uconnhead;
    uconnhead = puci;

    return(puci);
}


#define LABEL(str)(print_labels?str:"")

#define DESCR(ptr)\
	printf("\n"); \
	printf("%s%s \n",\
	       LABEL("Session Start: "),\
	       collie_time(&(ptr)->first_time));\
	printf("%s%s\n",\
	       LABEL("Session End: "),\
	       collie_time(&(ptr)->last_time));\
	printf("%s%s\n",\
	       LABEL("Source IP address: "),\
	       collie_dots((ptr)->addr_pair.a_address));\
	printf("%s%u\n",\
	       LABEL("Source Port: "),\
	       (unsigned)(ptr)->addr_pair.a_port);\
	printf("%s%s\n",\
	       LABEL("Source Fully Qualified domain name: "),\
	       collie_name((ptr)->addr_pair.a_address));\
	printf("%s%s\n",\
	       LABEL("Destination IP address: "),\
	       collie_dots((ptr)->addr_pair.b_address));\
	printf("%s%u\n",\
	       LABEL("Destination Port: "),\
	       (unsigned)(ptr)->addr_pair.b_port);\
	printf("%s%s\n",\
	       LABEL("Destination Fully Qualified domain name: "),\
	       collie_name((ptr)->addr_pair.b_address));\
	printf("%s%llu\n",\
	       LABEL("Bytes Transferred Source to Destination: "),\
	       (ptr)->a2b.data_bytes);\
	printf("%s%llu\n",\
	       LABEL("Bytes Transferred Destination to Source: "),\
	       (ptr)->b2a.data_bytes);\
	printf("%s%llu\n",\
	       LABEL("Packets Transferred Source to Destination: "),\
	       (ptr)->a2b.packets);\
	printf("%s%llu\n",\
	       LABEL("Packets Transferred Destination to Source: "),\
	       (ptr)->b2a.packets);


void	
collie_done(void)
{
    struct conn_info *pci;
    struct uconn_info *upci;
    struct stat statbuf;

    /* check the input file timestamp */
    if (stat(collie_filename,&statbuf) != 0) {
	perror(collie_filename);
	exit(-1);
    }
    
    /* print meta information */
    printf("\n");
    printf("%s%s\n",
	   LABEL("Source file: "),
	   collie_filename);
    printf("%s%s\n",
	   LABEL("File modification timestamp: "),
	   collie_date(statbuf.st_mtime));
    printf("%s%s\n",
	   LABEL("First packet: "),
	   collie_time(&first_packet));
    printf("%s%s\n",
	   LABEL("Last packet: "),
	   collie_time(&last_packet));

    /* print out the TCP connections */
    if (print_labels)
	printf("\nTCP Connections\n");
    for (pci=connhead; pci; pci=pci->next) {
	DESCR(pci->ptp)
	    }

    /* print out the UDP connections */
    if (print_labels)
	printf("\nUDP Connections\n");
    for (upci=uconnhead; upci; upci=upci->next) {
	DESCR(upci->pup)
	    }
}


/* called for each new file */
void
collie_newfile(
    char *newfile,
    u_long filesize,
    Bool fcompressed)
{
    if (collie_filename == NULL)
	collie_filename = strdup(newfile);
    else {
	fprintf(stderr,"\n\n\
Sorry, as the problem was defined, only a single file can be\n\
processed at a time\n");
	exit(-1);
    }
}


void
collie_usage(void)
{
    printf("\t-xcollie\"[-ln]\tprovide connection summary\n");
    printf("\t   -l	attach labels\n");
    printf("\t   -n	no labels please\n");
}


void *
collie_newconn(
    tcp_pair *ptp)
{
    struct conn_info *pci;

    pci = MakeConnRec();

    pci->ptp = ptp;
    
    return(pci);
}


void *
collie_newudpconn(
    udp_pair *pup)
{
    struct uconn_info *puci;

    puci = MakeUDPConnRec();

    puci->pup = pup;
    
    return(puci);
}


/* return the IP address in IPv4 or IPv6 dotted representation */
static char *collie_dots(
    ipaddr ipaddress)
{
    char *pch;
    int map = resolve_ipaddresses;

    resolve_ipaddresses = 0;
    pch = HostName(ipaddress);
    resolve_ipaddresses = map;

    return(pch);
}


/* convert the IP address to a name */
static char *collie_name(
    ipaddr ipaddress)
{
    char *pch;
    int map = resolve_ipaddresses;

    resolve_ipaddresses = 1;
    pch = HostName(ipaddress);
    resolve_ipaddresses = map;

    return(pch);
}



/* return a date stamp that we like */
/* Unix format: "Fri Sep 13 00:00:00 1986\n" */
/*		           1         2	     */
/*		 012345678901234567890123456 */
static char *
collie_date(
    time_t timestamp)
{
	struct tm *ptm;
	char *now;

	ptm = localtime(&timestamp);
	now = asctime(ptm);

	/* nuke the newline */
	now[24] = '\00';

	return(now);
}


/* return a time stamp that we like */
/* Unix format: "Fri Sep 13 00:00:00 1986\n" */
/*		           1         2	     */
/*		 012345678901234567890123456 */
static char *
collie_time(
    struct timeval *ptime)
{
	char *now;

	now = ts2ascii(ptime);

	return(now);
}

static void
ParseArgs(char *argstring)
{
    int argc;
    char **argv;
    int i;
    
    /* make sure there ARE arguments */
    if (!(argstring && *argstring))
	return;

    /* break the string into normal arguments */
    StringToArgv(argstring,&argc,&argv);

    /* check the module args */
    for (i=1; i < argc; ++i) {
	if (debug > 1)
	    printf("Checking argv[%d]:%s\n", i, argv[i]);
	if (strcmp(argv[i],"-d") == 0) {
	    debug = 1;
	} else if (strcmp(argv[i],"-l") == 0) {
	    print_labels = TRUE;
	} else if (strcmp(argv[i],"-n") == 0) {
	    print_labels = FALSE;
	} else {
	    fprintf(stderr,"Collie module: bad argument '%s'\n",
		    argv[i]);
	    exit(-1);
	}
    }
}


#endif /* LOAD_MODULE_COLLIE */
