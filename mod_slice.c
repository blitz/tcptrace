/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999
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

#ifdef LOAD_MODULE_SLICE

#include "tcptrace.h"
#include "mod_slice.h"

/* name of the file that slice data is dumped into */
#define SLICE_FILENAME "slice.dat"

/* argument flags */
static float slice_interval = 15.0;  /* 15 seconds by default */
static timeval tv_slice_interval;

/* local debugging flag */
static int debug = 0;




/* info that I keep about each connection */
struct conn_info {
    u_long last_rexmits;	/* for detecting rexmits */
    u_long last_active_slice;	/* for checking activity */
};


/* counters that we keep for each interval */
static struct slice_counters {
    /* active conns */
    u_long n_active;

    /* connection opens/closes */
    u_long n_opens;

    /* bytes/segments (including rexmits) */
    u_long n_bytes;
    u_long n_segs;

    /* bytes/segments that are rexmitted */
    u_long n_rexmit_bytes;
    u_long n_rexmit_segs;
} info;


/* local routines */
static void AgeSlice(timeval *);
static void ParseArgs(char *argstring);


/* globals */
static u_long slice_number = 1;	/* while slice interval are we in? */






/* Set things up */
int
slice_init(
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
	    if (strncasecmp(argv[i]+2,"slice",sizeof("slice")-1) == 0) {
		/* I want to be called */
		args = argv[i]+(sizeof("-xslice")-1);
		enable = 1;
		argv[i] = NULL;
	    }
	}
    }

    if (!enable)
	return(0);	/* don't call me again */

    /* parse the encoded args */
    ParseArgs(args);

    /* turn the slice interval into a timeval */
    tv_slice_interval.tv_sec = (int)slice_interval;
    tv_slice_interval.tv_usec =
	1000000 * (slice_interval - tv_slice_interval.tv_sec);

    /* tell them what's happening */
    printf("mod_slice: generating data in %.3fsec slices to file %s\n",
	   slice_interval, SLICE_FILENAME);
    if (debug)
	printf("Slice interval tv: %u.%06u\n",
	       (unsigned)tv_slice_interval.tv_sec,
	       (unsigned)tv_slice_interval.tv_usec);

    /* init the graphs and etc... */
    AgeSlice(NULL);

    return(1);	/* TRUE means call slice_read and slice_done later */
}




void
slice_read(
    struct ip *pip,		/* the packet */
    tcp_pair *ptp,		/* info I have about this connection */
    void *plast,		/* past byte in the packet */
    void *mod_data)		/* connection info for this one */
{
    u_long bytes = ntohs(pip->ip_len);
    static timeval next_time = {0,0};
    struct conn_info *pci = mod_data;
    int was_rexmit = 0;

    /* if this is the first packet, determine the END of the slice */
    if (ZERO_TIME(&next_time)) {
	next_time = current_time;
	tv_add(&next_time, tv_slice_interval);
    }

    /* if we've gone over our interval, print out data so far */
    while (tv_ge(current_time,next_time)) {
	/* output a line */
	AgeSlice(&next_time);

	/* when does the next interval start? */
	tv_add(&next_time, tv_slice_interval);
    }

    /* see if it was a retransmission */
    if (pci->last_rexmits != ptp->a2b.rexmit_pkts+ptp->b2a.rexmit_pkts) {
	pci->last_rexmits = ptp->a2b.rexmit_pkts+ptp->b2a.rexmit_pkts;
	was_rexmit = 1;
    }

    /* add to total data counters */
    ++info.n_segs;
    info.n_bytes += bytes;
    if (was_rexmit) {
	info.n_rexmit_segs += 1;
	info.n_rexmit_bytes += bytes;
    }

    /* if it hasn't already been active in this slice interval, count it*/
    /* (avoids having to zero lots of counters!) */
    if (pci->last_active_slice != slice_number) {
	pci->last_active_slice = slice_number;
	++info.n_active;
    }
    

}



static void
AgeSlice(
    timeval *pnow)
{
    char *pch_now;
    static MFILE *pmf = NULL;

    

    /* first time doesn't count */
    if (pnow == NULL) {
	/* open the output file */
	pmf = Mfopen(SLICE_FILENAME,"w");

	/* print the headers */
	Mfprintf(pmf,"\
time                segs    bytes  rexsegs rexbytes      new   active\n\
--------------- -------- -------- -------- -------- -------- --------\n");
	return;
    }

    /* format the current time */
    pch_now = ts2ascii(pnow);
    /* remove the year */
    pch_now[26] = '\00';
    /* remove the month and stuff */
    pch_now += 11;  /* strlen("Fri Jan 12 ") */

    /* print the stats collected */
    Mfprintf(pmf, "%s %8lu %8lu %8lu %8lu %8lu %8lu\n",
	     pch_now,
	     info.n_segs,
	     info.n_bytes,
	     info.n_rexmit_segs,
	     info.n_rexmit_bytes,
	     info.n_opens,
	     info.n_active);


    /* zero out the counters */
    memset(&info, 0, sizeof(info));
    

    /* new slice interval */
    ++slice_number;
}


void	
slice_done(void)
{
    /* print the last few packets */
    AgeSlice(&current_time);
}




void *
slice_newconn(
    tcp_pair *ptp)
{
    struct conn_info *pci;
    
    ++info.n_opens;

    pci = MallocZ(sizeof(struct conn_info));

    return(pci);
}


void
slice_usage(void)
{
    printf("\
\t-xslice\"[ARGS]\"\tprint data info in slices\n\
\t   module argument format:\n\
\t       -iS   set slice interval to S (float) seconds, default 15.0\n\
\t       -d    enable local debugging in this module\n\
");
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
	float interval;
	if (debug > 1)
	    printf("Checking argv[%d]: '%s'\n", i, argv[i]);
	if (strcmp(argv[i],"-d") == 0) {
	    ++debug;
	} else if (sscanf(argv[i],"-i%f", &interval) == 1) {
	    slice_interval = interval;
	    if (debug)
		printf("mod_slice: setting slice interval to %.3f seconds\n",
		       slice_interval);
	} else {
	    fprintf(stderr,"Slice module: bad argument '%s'\n",
		    argv[i]);
	    exit(-1);
	}
    }
}


#endif /* LOAD_MODULE_SLICE */
