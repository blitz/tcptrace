/* 
 * tcptrace.c - turn protocol monitor traces into xplot
 * 
 * Author:	Shawn Ostermann
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#include "tcptrace.h"


void
DoThru(
    tcb *ptcb,
    int nbytes)
{
    u_long etime;
    double thruput;

    /* init, if not already done */
    if (ptcb->thru_firsttime.tv_sec == 0) {
	char title[210];

	ptcb->thru_firsttime = current_time;
	ptcb->thru_pkts = 1;
	ptcb->thru_bytes = nbytes;

	/* create the plotter file */
	sprintf(title,"%s_==>_%s",
		ptcb->ptp->a_endpoint, ptcb->ptp->b_endpoint);
	ptcb->thru_plotter = new_plotter(ptcb,title,"tput");

	return;
    }

    /* see if we should output the stats yet */
    if (ptcb->thru_pkts+1 >= thru_interval) {

	/* compute stats for this interval */
	etime = elapsed(ptcb->thru_firsttime,current_time);
	thruput = (double) ptcb->thru_bytes / ((double) etime / 1000000.0);

	plotter_line(ptcb->thru_plotter,
		     ptcb->thru_firsttime, (int) ptcb->thru_lastthru,
		     current_time, (int) thruput);

	/* reset stats for this interval */
	ptcb->thru_firsttime = current_time;
	ptcb->thru_pkts = 0;
	ptcb->thru_bytes = 0;
	ptcb->thru_lastthru = (int) thruput;
    }

    /* add in the latest packet */
    ++ptcb->thru_pkts;
    ptcb->thru_bytes += nbytes;
}
