/*
 * Copyright (c) 1994, 1995, 1996, 1997
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
static char const rcsid_collie[] =
   "$Id$";

#ifdef LOAD_MODULE_COLLIE

#include "tcptrace.h"
#include "mod_collie.h"



/* additional info kept per connection */
struct conn_info {
    tcp_pair *ptp;
    struct conn_info *next;
};
static struct conn_info *connhead = NULL;



/* local routines */
static struct conn_info *MakeConnRec(void);
static char *collie_name(ipaddr ipaddress);
static char *collie_dots(ipaddr ipaddress);
static char *collie_time(struct timeval *ptime);
static char *collie_date(struct timeval *ptime);

/* other globals */



/* Set it up */
int
collie_init(
    int argc,
    char *argv[])
{
    int i;
    int enable=0;

    for (i=1; i < argc; ++i) {
	if (!argv[i])
	    continue;  /* argument already taken by another module... */
	if (strncmp(argv[i],"-x",2) == 0) {
	    if (strncasecmp(argv[i]+2,"collie",sizeof("collie")-1) == 0) {
		/* I want to be called */
		enable = 1;
		argv[i] = NULL;
	    }
	}
    }

    if (!enable)
	return(0);	/* don't call me again */

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


void	
collie_done(void)
{
    struct conn_info *pci;

    /* print them out */
    for (pci=connhead; pci; pci=pci->next) {
	tcp_pair *ptp = pci->ptp;

	printf("\n\n");

	printf("Date: %s\n", 
	       collie_date(&ptp->first_time));
	printf("Session Start: %s \n",
	       collie_time(&ptp->first_time));
	printf("Session End: %s\n",
	       collie_time(&ptp->last_time));
	printf("Source IP address and Port: %s %u\n",
	       collie_dots(ptp->addr_pair.a_address),
	       (unsigned)ptp->addr_pair.a_port);
	printf("Source Fully Qualified domain name: %s\n",
	       collie_name(ptp->addr_pair.a_address));
	printf("Destination IP address and Port: %s %u\n",
	       collie_dots(ptp->addr_pair.b_address),
	       (unsigned)ptp->addr_pair.b_port);
	printf("Destination Fully Qualified domain name: %s\n",
	       collie_name(ptp->addr_pair.b_address));
	printf("Bytes Transferred Source to Destination: %llu\n",
	       ptp->a2b.data_bytes);
	printf("Bytes Transferred Destination to Source: %llu\n",
	       ptp->b2a.data_bytes);
    }
}


void
collie_usage(void)
{
    printf("\t-xcollie\tprovide connection summary\n");
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

static char *collie_dots(
    ipaddr ipaddress)
{
    char *pch;
    int map = nonames;

    nonames = 1;
    pch = HostName(ipaddress);
    nonames = map;

    return(pch);
}

static char *collie_name(
    ipaddr ipaddress)
{
    char *pch;
    int map = nonames;

    nonames = 0;
    pch = HostName(ipaddress);
    nonames = map;

    return(pch);
}


/* Unix format: "Fri Sep 13 00:00:00 1986\n" */
/*		           1         2	     */
/*		 012345678901234567890123456 */
static char *
collie_date(
    struct timeval *ptime)
{
	struct tm *ptm;
	char *now;

	if (ZERO_TIME(ptime))
	    return("        <the epoch>       ");

	ptm = localtime(&ptime->tv_sec);
	now = asctime(ptm);

	/* nuke the newline */
	now[24] = '\00';

	return(now);
}


/* Unix format: "Fri Sep 13 00:00:00 1986\n" */
static char *
collie_time(
    struct timeval *ptime)
{
	char *now;

	now = ts2ascii(ptime);

	return(now+11);
}



#endif /* LOAD_MODULE_COLLIE */
