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
	MFILE *f;
	static char filename[15];

	ptcb->thru_firsttime = current_time;
	ptcb->thru_pkts = 1;
	ptcb->thru_bytes = nbytes;

	/* open the output file */
	sprintf(filename,"%s2%s.tput",
		ptcb->host_letter, ptcb->ptwin->host_letter);

	if ((f = Mfopen(filename,"w")) == NULL) {
	    perror(filename);
	    ptcb->thru_dump_file = (MFILE *) -1;
	}

	if (debug)
	    fprintf(stderr,"Throughput Sample file is '%s'\n", filename);

	ptcb->thru_dump_file = f;
	
	return;
    }

    /* see if we should output the stats yet */
    if (ptcb->thru_pkts+1 >= thru_interval) {

	/* compute stats for this interval */
	etime = elapsed(ptcb->thru_firsttime,current_time);
	thruput = (double) ptcb->thru_bytes / ((double) etime / 1000000.0);

	Mfprintf(ptcb->thru_dump_file, "%lu.%06lu %d\n",
	       current_time.tv_sec,
	       current_time.tv_usec,
	       (int) thruput);

	/* reset stats for this interval */
	ptcb->thru_firsttime = current_time;
	ptcb->thru_pkts = 0;
	ptcb->thru_bytes = 0;
    }

    /* add in the latest packet */
    ++ptcb->thru_pkts;
    ptcb->thru_bytes += nbytes;
}
