/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *               2002, 2003, 2004
 *	Ohio University.
 *
 * ---
 * 
 * Starting with the release of tcptrace version 6 in 2001, tcptrace
 * is licensed under the GNU General Public License (GPL).  We believe
 * that, among the available licenses, the GPL will do the best job of
 * allowing tcptrace to continue to be a valuable, freely-available
 * and well-maintained tool for the networking community.
 *
 * Previous versions of tcptrace were released under a license that
 * was much less restrictive with respect to how tcptrace could be
 * used in commercial products.  Because of this, I am willing to
 * consider alternate license arrangements as allowed in Section 10 of
 * the GNU GPL.  Before I would consider licensing tcptrace under an
 * alternate agreement with a particular individual or company,
 * however, I would have to be convinced that such an alternative
 * would be to the greater benefit of the networking community.
 * 
 * ---
 *
 * This file is part of Tcptrace.
 *
 * Tcptrace was originally written and continues to be maintained by
 * Shawn Ostermann with the help of a group of devoted students and
 * users (see the file 'THANKS').  The work on tcptrace has been made
 * possible over the years through the generous support of NASA GRC,
 * the National Science Foundation, and Sun Microsystems.
 *
 * Tcptrace is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Tcptrace is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tcptrace (in the file 'COPYING'); if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 *		http://www.tcptrace.org/
 */
#include "tcptrace.h"
static char const GCC_UNUSED rcsid[] =
   "$Header$";

#ifdef LOAD_MODULE_SLICE

#include "mod_slice.h"

/* name of the file that slice data is dumped into */
#define SLICE_FILENAME "slice.dat"

/* time and date formats */
enum t_time_format {tf_long=1, tf_brief=2, tf_unix=3, tf_unix_long=4};

/* argument flags */
static float slice_interval = 15.0;  /* 15 seconds by default */
static timeval tv_slice_interval;
static enum t_time_format time_format = tf_brief;

/* local debugging flag */
static int ldebug = 0;




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
    if (ldebug)
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
%s     segs    bytes  rexsegs rexbytes      new   active\n\
%s -------- -------- -------- -------- -------- --------\n",
		 (time_format == tf_long)?	"date                           ":
		 (time_format == tf_brief)?	"date           ":
		 (time_format == tf_unix)?	"date     ":
		 (time_format == tf_unix_long)?	"date            ":"UNKNOWN",

		 (time_format == tf_long)?	"-------------------------------":
		 (time_format == tf_brief)?	"---------------":
		 (time_format == tf_unix)?	"---------":
		 (time_format == tf_unix_long)?	"----------------":"UNKNOWN"
		 );
	return;
    }

    /* format the current time */
    pch_now = ts2ascii(pnow);
    if (time_format == tf_brief) {
	/* remove the year */
	pch_now[26] = '\00';
	/* remove the month and stuff */
	pch_now += 11;  /* strlen("Fri Jan 12 ") */
    }

    /* print the stats collected */
    switch(time_format) {
      case tf_long:
      case tf_brief:
	Mfprintf(pmf, "%s", pch_now); break;
      case tf_unix:
	Mfprintf(pmf, "%8lu", pnow->tv_sec); break;
      case tf_unix_long:
	Mfprintf(pmf, "%8lu.%06u", pnow->tv_sec, pnow->tv_usec); break;
    }
    Mfprintf(pmf, " %8lu %8lu %8lu %8lu %8lu %8lu\n",
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
\t       -tb   specify time and date 'briefly'\n\
\t       -tl   specify time and date in long, 'Unix Format'\n\
\t       -tu   specify time and date as a Unix timestamp (secs)\n\
\t       -tU   specify time and date as a Unix timestamp (secs.usecs)\n\
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
	if (ldebug > 1)
	    printf("Checking argv[%d]: '%s'\n", i, argv[i]);
	if (strcmp(argv[i],"-d") == 0) {
	    ++ldebug;
	} else if (strncmp(argv[i],"-t",2) == 0) {
	    switch (argv[i][2]) {
	      case 'u': time_format = tf_unix; break;
	      case 'U': time_format = tf_unix_long; break;
	      case 'l': time_format = tf_long; break;
	      case 'b': time_format = tf_brief; break;
	      default:
		fprintf(stderr,"Bad -t option ('%s') for slice module\n", argv[i]);
		slice_usage();
		exit(-1);
	    }
	} else if (sscanf(argv[i],"-i%f", &interval) == 1) {
	    slice_interval = interval;
	    if (ldebug)
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
