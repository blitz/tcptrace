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
static char const copyright[] =
    "@(#)Copyright (c) 1998 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


#include "tcptrace.h"


void
DoThru(
    tcb *ptcb,
    int nbytes)
{
    double etime;
    double thruput;

    /* init, if not already done */
    if (ZERO_TIME(&ptcb->thru_firsttime)) {
	char title[210];

	ptcb->thru_firsttime = current_time;
	ptcb->thru_lasttime = current_time;
	ptcb->thru_pkts = 1;
	ptcb->thru_bytes = nbytes;

	/* create the plotter file */
	sprintf(title,"%s_==>_%s (throughput)",
		ptcb->ptp->a_endpoint, ptcb->ptp->b_endpoint);
	ptcb->thru_plotter = new_plotter(ptcb,NULL,title,
					 "time","thruput (bytes/sec)",
					 THROUGHPUT_FILE_EXTENSION);

	return;
    }

    /* if no data, then nothing to do */
    if (nbytes == 0)
	return;

    /* see if we should output the stats yet */
    if (ptcb->thru_pkts+1 >= thru_interval) {

	/* compute stats for this interval */
	etime = elapsed(ptcb->thru_firsttime,current_time);
	if (etime == 0.0)
	    etime = 1000;	/* ick, what if "no time" has passed?? */
	thruput = (double) ptcb->thru_bytes / ((double) etime / 1000000.0);

	/* instantaneous plot */
	plotter_temp_color(ptcb->thru_plotter,"red");
	plotter_line(ptcb->thru_plotter,
		     ptcb->thru_firsttime, (int) ptcb->thru_lastthru_i,
		     current_time, (int) thruput);
	ptcb->thru_lastthru_i = (int) thruput;

	/* compute stats for connection lifetime */
	etime = elapsed(ptcb->ptp->first_time,current_time);
	if (etime == 0.0)
	    etime = 1000;	/* ick, what if "no time" has passed?? */
	thruput = (double) ptcb->data_bytes / ((double) etime / 1000000.0);

	/* long-term average */
	plotter_temp_color(ptcb->thru_plotter,"blue");
	plotter_line(ptcb->thru_plotter,
		     ptcb->thru_firsttime, (int) ptcb->thru_lastthru_t,
		     current_time, (int) thruput);
	ptcb->thru_lastthru_t = (int) thruput;

	/* reset stats for this interval */
	ptcb->thru_firsttime = current_time;
	ptcb->thru_pkts = 0;
	ptcb->thru_bytes = 0;
    }

    /* immediate value in yellow ticks */
    if (plot_tput_instant) {
	etime = elapsed(ptcb->thru_lasttime,current_time);
	if (etime == 0.0)
	    etime = 1000;	/* ick, what if "no time" has passed?? */
	thruput = (double) nbytes / ((double) etime / 1000000.0);
	plotter_temp_color(ptcb->thru_plotter,"yellow");
	plotter_dot(ptcb->thru_plotter,
		    current_time, (int) thruput);
    }

    /* add in the latest packet */
    ptcb->thru_lasttime = current_time;
    ++ptcb->thru_pkts;
    ptcb->thru_bytes += nbytes;
}
