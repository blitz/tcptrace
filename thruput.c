/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001
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
static char const copyright[] =
    "@(#)Copyright (c) 2001 -- Ohio University.\n";
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
    char *myname, *hisname;

    /* init, if not already done */
    if (ZERO_TIME(&ptcb->thru_firsttime)) {
	char title[210];

	ptcb->thru_firsttime = current_time;
	ptcb->thru_lasttime = current_time;
	ptcb->thru_pkts = 1;
	ptcb->thru_bytes = nbytes;
	

	/* bug fix from Michele Clark - UNC */
	if (&ptcb->ptp->a2b == ptcb) {
	    myname = ptcb->ptp->a_endpoint;
	    hisname = ptcb->ptp->b_endpoint;
	} else {
	    myname = ptcb->ptp->b_endpoint;
	    hisname = ptcb->ptp->a_endpoint;
	}
	/* create the plotter file */
	sprintf(title,"%s_==>_%s (throughput)",
		myname, hisname);
	ptcb->thru_plotter = new_plotter(ptcb,NULL,title,
					 "time","thruput (bytes/sec)",
					 THROUGHPUT_FILE_EXTENSION);
	if (graph_time_zero) {
	    /* set graph zero points */
	    plotter_nothing(ptcb->thru_plotter, current_time);
	}

	/* create lines for average and instantaneous values */
	ptcb->thru_avg_line =
	    new_line(ptcb->thru_plotter, "avg. tput", "blue");
	ptcb->thru_inst_line =
	    new_line(ptcb->thru_plotter, "inst. tput", "red");

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
	extend_line(ptcb->thru_inst_line,
		     current_time, (int) thruput);

	/* compute stats for connection lifetime */
	etime = elapsed(ptcb->ptp->first_time,current_time);
	if (etime == 0.0)
	    etime = 1000;	/* ick, what if "no time" has passed?? */
	thruput = (double) ptcb->data_bytes / ((double) etime / 1000000.0);

	/* long-term average */
	extend_line(ptcb->thru_avg_line,
		     current_time, (int) thruput);

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
