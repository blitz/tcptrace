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
#include "gcache.h"
#include <math.h>


/* local routines */
static u_int SynCount(tcp_pair *);
static u_int FinCount(tcp_pair *);
static double Average(double, int);
static double Stdev(double, double, int);




static u_int
SynCount(
    tcp_pair *ptp)
{
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;

    return(((pab->syn_count >= 1)?1:0) +
	   ((pba->syn_count >= 1)?1:0));
}



static u_int
FinCount(
    tcp_pair *ptp)
{
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;

    return(((pab->fin_count >= 1)?1:0) +
	   ((pba->fin_count >= 1)?1:0));
}



int
ConnComplete(
    tcp_pair *ptp)
{
    return(SynCount(ptp) >= 2 && FinCount(ptp) >= 2);
}


int
ConnReset(
    tcp_pair *ptp)
{
    return(ptp->a2b.reset_count + ptp->b2a.reset_count != 0);
}



static double
Average(
    double sum,
    int count)
{
    return((double) sum / ((double)count+.0001));
}



static double
Stdev(
    double sum,
    double sum2,
    int n)
{
    double term;
    double term1;
    double term2;

    if (n<=2)
	return(0.0);

    term1 = sum2;
    term2 = (sum * sum) / (double)n;
    term = term1-term2;
    term /= (double)(n-1);
    return(sqrt(term));
}




void
PrintBrief(
    tcp_pair *ptp)
{
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;

    fprintf(stdout,"%s <==> %s", ptp->a_endpoint, ptp->b_endpoint);
    fprintf(stdout,"  %s2%s:%lu",
	    pab->host_letter,
	    pba->host_letter,
	    pab->packets);
    fprintf(stdout,"  %s2%s:%lu",
	    pba->host_letter,
	    pab->host_letter,
	    pba->packets);
    if (ConnComplete(ptp))
	fprintf(stdout,"  (complete)");
    if (ConnReset(ptp))
	fprintf(stdout,"  (reset)");
    fprintf(stdout,"\n");
}


void
PrintTrace(
    tcp_pair *ptp)
{
    unsigned long etime;
    float etime_float;
    float thru_float;
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;
    char *host1 = pab->host_letter;
    char *host2 = pba->host_letter;

    fprintf(stdout,"\thost %s:        %s\n", host1, ptp->a_endpoint);
    fprintf(stdout,"\thost %s:        %s\n", host2, ptp->b_endpoint);
    fprintf(stdout,"\tcomplete conn: %s",
	    ConnReset(ptp)?"RESET":(
		ConnComplete(ptp)?"yes":"no"));
    if (ConnComplete(ptp))
	fprintf(stdout,"\n");
    else
	fprintf(stdout,"\t(SYNs: %u)  (FINs: %u)\n",
		SynCount(ptp), FinCount(ptp));

    fprintf(stdout,"\tfirst packet:  %s\n", ts2ascii(&ptp->first_time));
    fprintf(stdout,"\tlast packet:   %s\n", ts2ascii(&ptp->last_time));

    etime = elapsed(ptp->first_time,ptp->last_time);
    fprintf(stdout,"\telapsed time:  %lu:%02lu:%02lu.%04lu\n",
	    (etime / 1000000) / (60 * 24),
	    (etime / 1000000) % (60 * 24) / 60,
	    ((etime / 1000000) % (60 * 24)) % 60,
	    (etime % 1000000) / 100);
    fprintf(stdout,"\ttotal packets: %lu\n", ptp->packets);
	

    fprintf(stdout,"    %s->%s:\t\t\t    %s->%s:\n",
	    host1,host2,host2,host1);

    fprintf(stdout,
	    "\tdata packets:  %8lu\t\tdata packets:  %8lu\n",
	    pab->data_pkts,
	    pba->data_pkts);
    fprintf(stdout,
	    "\tdata bytes:    %8lu\t\tdata bytes:    %8lu\n",
	    pab->data_bytes,
	    pba->data_bytes);
    fprintf(stdout,
	    "\trexmt packets: %8lu\t\trexmt packets: %8lu\n",
	    pab->rexmit_pkts,
	    pba->rexmit_pkts);
    fprintf(stdout,
	    "\trexmt bytes:   %8lu\t\trexmt bytes:   %8lu\n",
	    pab->rexmit_bytes,
	    pba->rexmit_bytes);
    fprintf(stdout,
	    "\tunique packets: %7lu\t\tdata packets:  %8lu\n",
	    pab->data_pkts-pab->rexmit_pkts,
	    pba->data_pkts-pba->rexmit_pkts);
    fprintf(stdout,
	    "\tunique bytes:  %8lu\t\tdata bytes:    %8lu\n",
	    pab->data_bytes-pab->rexmit_bytes,
	    pba->data_bytes-pba->rexmit_bytes);
    fprintf(stdout,
	    "\tack pkts sent: %8lu\t\tack pkts sent: %8lu\n",
	    pab->ack_pkts,
	    pba->ack_pkts);
    fprintf(stdout,
	    "\tmax win adv:   %8lu\t\tmax win adv:   %8lu\n",
	    pab->win_max,
	    pba->win_max);
    fprintf(stdout,
	    "\tavg win adv:   %8lu\t\tavg win adv:   %8lu\n",
	    pab->ack_pkts==0?0:pab->win_tot/pab->ack_pkts,
	    pba->ack_pkts==0?0:pba->win_tot/pba->ack_pkts);
    fprintf(stdout,
	    "\tzero win adv:  %8lu\t\tzero win adv:  %8lu\n",
	    pab->win_zero_ct,
	    pba->win_zero_ct);

    fprintf(stdout,
	    "\ttotal packets: %8lu\t\ttotal packets: %8lu\n",
	    pab->packets,
	    pba->packets);
    etime_float = (float) etime / 1000000.0;
    if ((pab->data_bytes-pab->rexmit_bytes == 0) || (etime_float == 0.0))
	thru_float = 0.0;
    else
	thru_float = (float) (pab->data_bytes-pab->rexmit_bytes) / etime_float;
    if (thru_float == 0)
	fprintf(stdout, "\tthroughput:          NA    ");
    else
	fprintf(stdout, "\tthroughput:    %8.0f Bps", thru_float);

    if ((pba->data_bytes-pab->rexmit_bytes == 0) || (etime_float == 0.0))
	thru_float = 0.0;
    else
    thru_float = (float) (pba->data_bytes-pba->rexmit_bytes) / etime_float;
    if (thru_float == 0)
	fprintf(stdout, "\tthroughput:          NA\n");
    else
	fprintf(stdout, "\tthroughput:    %8.0f Bps\n", thru_float);

    if (dortt) {
	fprintf(stdout,"\n");
	fprintf(stdout,
		"\tRTT samples:   %8lu\t\tRTT samples:   %8lu\n",
		pab->rtt_count, pba->rtt_count);
	fprintf(stdout,
		"\tRTT min:       %8.1f ms\tRTT min:       %8.1f ms\n",
		(double)pab->rtt_min/1000.0, (double)pba->rtt_min/1000.0);
	fprintf(stdout,
		"\tRTT max:       %8.1f ms\tRTT max:       %8.1f ms\n",
		(double)pab->rtt_max/1000.0, (double)pba->rtt_max/1000.0);
	fprintf(stdout,
		"\tRTT avg:       %8.1f ms\tRTT avg:       %8.1f ms\n",
		Average(pab->rtt_sum, pab->rtt_count) / 1000.0,
		Average(pba->rtt_sum, pba->rtt_count) / 1000.0);
	fprintf(stdout,
		"\tRTT stdev:     %8.1f ms\tRTT stdev:     %8.1f ms\n",
		Stdev(pab->rtt_sum, pab->rtt_sum2, pab->rtt_count) / 1000.0,
		Stdev(pba->rtt_sum, pba->rtt_sum2, pba->rtt_count) / 1000.0);

        if (pab->rtt_amback || pba->rtt_amback) {
	    fprintf(stdout, "\
\t  For the following 5 RTT statistics, only ACKs for
\t  multiply-transmitted segments (ambiguous ACKs) were
\t  considered.  Times are taken from the last instance
\t  of a segment.
");
	    fprintf(stdout,
		    "\tambiguous acks: %7lu\t\tambiguous acks: %7lu\n",
		    pab->rtt_amback, pba->rtt_amback);
	    fprintf(stdout,
		    "\tRTT min (last): %7.1f ms\tRTT min (last): %7.1f ms\n",
		    (double)pab->rtt_min_last/1000.0,
		    (double)pba->rtt_min_last/1000.0);
	    fprintf(stdout,
		    "\tRTT max (last): %7.1f ms\tRTT max (last): %7.1f ms\n",
		    (double)pab->rtt_max_last/1000.0,
		    (double)pba->rtt_max_last/1000.0);
	    fprintf(stdout,
		    "\tRTT avg (last): %7.1f ms\tRTT avg (last): %7.1f ms\n",
		    Average(pab->rtt_sum_last, pab->rtt_count_last) / 1000.0,
		    Average(pba->rtt_sum_last, pba->rtt_count_last) / 1000.0);
	    fprintf(stdout,
		    "\tRTT sdv (last): %7.1f ms\tRTT sdv (last): %7.1f ms\n",
		    Stdev(pab->rtt_sum_last, pab->rtt_sum2_last, pab->rtt_count_last) / 1000.0,
		    Stdev(pba->rtt_sum_last, pba->rtt_sum2_last, pba->rtt_count_last) / 1000.0);
	}

	fprintf(stdout,
		"\tsegs cum acked: %7lu\t\tsegs cum acked: %7lu\n",
		pab->rtt_cumack, pba->rtt_cumack);
	fprintf(stdout,
		"\tredundant acks: %7lu\t\tredundant acks: %7lu\n",
		pab->rtt_unkack, pba->rtt_unkack);
	if (debug)
	    fprintf(stdout,
		    "\tunknown acks:  %8lu\t\tunknown acks:  %8lu\n",
		    pab->rtt_unkack, pba->rtt_unkack);
	fprintf(stdout,
		"\tmax # retrans: %8lu\t\tmax # retrans: %8lu\n",
		pab->retr_max, pba->retr_max);
	fprintf(stdout,
		"\tmin retr time: %8.1f ms\tmin retr time: %8.1f ms\n",
		(double)pab->retr_min_tm/1000.0,
		(double)pba->retr_min_tm/1000.0);
	fprintf(stdout,
		"\tmax retr time: %8.1f ms\tmax retr time: %8.1f ms\n",
		(double)pab->retr_max_tm/1000.0,
		(double)pba->retr_max_tm/1000.0);
	fprintf(stdout,
		"\tavg retr time: %8.1f ms\tavg retr time: %8.1f ms\n",
		Average(pab->retr_tm_sum, pab->retr_tm_count) / 1000.0,
		Average(pba->retr_tm_sum, pba->retr_tm_count) / 1000.0);
	fprintf(stdout,
		"\tsdv retr time: %8.1f ms\tsdv retr time: %8.1f ms\n",
		Stdev(pab->retr_tm_sum, pab->retr_tm_sum2, pab->retr_tm_count) / 1000.0,
		Stdev(pba->retr_tm_sum, pba->retr_tm_sum2, pba->retr_tm_count) / 1000.0);
    }
}
