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
	ptcb->thru_lasttime = current_time;
	ptcb->thru_pkts = 1;
	ptcb->thru_bytes = nbytes;

	/* create the plotter file */
	sprintf(title,"%s_==>_%s (throughput)",
		ptcb->ptp->a_endpoint, ptcb->ptp->b_endpoint);
	ptcb->thru_plotter = new_plotter(ptcb,title,
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
    etime = elapsed(ptcb->thru_lasttime,current_time);
    if (etime == 0.0)
	etime = 1000;	/* ick, what if "no time" has passed?? */
    thruput = (double) nbytes / ((double) etime / 1000000.0);
    plotter_temp_color(ptcb->thru_plotter,"yellow");
    plotter_diamond(ptcb->thru_plotter,
		    current_time, (int) thruput);

    /* add in the latest packet */
    ptcb->thru_lasttime = current_time;
    ++ptcb->thru_pkts;
    ptcb->thru_bytes += nbytes;
}
