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
    double computed_thruput;

    /* if no data, ignore this packet */
    if (nbytes == 0)
	return;

    /* init, if not already done */
    if (ptcb->thru_firsttime.tv_sec == 0) {
	char title[210];

	ptcb->thru_firsttime = current_time;
	ptcb->thru_bytes = nbytes;

	/* create the plotter file */
	sprintf(title,"%s_==>_%s (throughput)",
		ptcb->ptp->a_endpoint, ptcb->ptp->b_endpoint);
	ptcb->thru_plotter = new_plotter(ptcb,title,
					 
					 THROUGHPUT_FILE_EXTENSION);
	plotter_perm_color(ptcb->thru_plotter,"red");

	return;
    }

    /* running total, alpha/beta model */
    etime = elapsed(ptcb->thru_firsttime,current_time);
    /* sanity check, if timestamps were the same, then etime is 0 */
    /* and throughput computation will yield infinite */
    /* (probably from packet grabber with lousy timestamps) */
    if (etime == 0) {
	ptcb->thru_bytes += nbytes;
	return;
    }
    thruput = (double) ptcb->thru_bytes * 1000000.0 / (double) etime;
    if (ptcb->thru_lastthru == 0.0)
	ptcb->thru_lastthru = thruput;  /* prime the pump */
    printf("%5ld bytes in %9ld us = %d bytes/second\n",
	   ptcb->thru_bytes, etime, (int)thruput);

#define ALPHA	1.00
#define BETA	(1.0 - ALPHA)
    computed_thruput = ALPHA*thruput + BETA*ptcb->thru_lastthru;
#define MATH_IS_HARD
#ifdef MATH_IS_HARD
    printf("Thru: new:%f  old:%f  result:%f\n",
	   thruput, ptcb->thru_lastthru, computed_thruput);
#endif MATH_IS_HARD

    plotter_line(ptcb->thru_plotter,
		 ptcb->thru_firsttime, (int) ptcb->thru_lastthru,
		 current_time, (int) computed_thruput);

    /* reset counters for next interval */
    ptcb->thru_firsttime = current_time;
    ptcb->thru_bytes = nbytes;
    ptcb->thru_lastthru = computed_thruput;
}
