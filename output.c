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
static void StatlineI(char *, char *, char *, u_long, u_long);
static void StatLineF(char *, char *, char *, double, double);
static void StatLineField(char *, char *, char *, u_long, int);
static void StatLineFieldF(char *, char *, char *, double, int);
static void StatLineOne(char *, char *, char *);




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
    static char infobuf[100];

    sprintf(infobuf,"%s - %s",
	    ptp->a_endpoint,
	    ptp->b_endpoint);
    fprintf(stdout,"%-60s", infobuf);
    fprintf(stdout," %4lu>", pab->packets);
    fprintf(stdout," %4lu<", pba->packets);
    if (ConnComplete(ptp))
	fprintf(stdout,"  (complete)");
    if (ConnReset(ptp))
	fprintf(stdout,"  (reset)");
    fprintf(stdout,"\n");
}


#ifdef OLDVERSION
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
#endif OLDVERSION



void
PrintTrace(
    tcp_pair *ptp)
{
    unsigned long etime;
    double etime_float;
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
	

    fprintf(stdout,"   %s->%s:			      %s->%s:\n",
	    host1,host2,host2,host1);

    StatlineI("total packets","","%8lu", pab->packets, pba->packets);
    if (pab->reset_count || pba->reset_count)
	StatlineI("resets sent","","%8lu", pab->reset_count, pba->reset_count);
    StatlineI("ack pkts sent","","%8lu", pab->ack_pkts, pba->ack_pkts);
    StatlineI("unique bytes","","%8lu",
	      pab->data_bytes-pab->rexmit_bytes,
	      pba->data_bytes-pba->rexmit_bytes);
#ifdef OLD
    StatlineI("unique packets","","%8lu",
	      pab->data_pkts-pab->rexmit_pkts,
	      pba->data_pkts-pba->rexmit_pkts);
#endif OLD
    StatlineI("actual data pkts","","%8lu", pab->data_pkts, pba->data_pkts);
    StatlineI("actual data bytes","","%8lu", pab->data_bytes, pba->data_bytes);
    StatlineI("rexmt data pkts","","%8lu", pab->rexmit_pkts, pba->rexmit_pkts);
    StatlineI("rexmt data bytes","","%8lu", pab->rexmit_bytes, pba->rexmit_bytes);
    StatlineI("outoforder pkts","","%8lu", pab->out_order_pkts, pba->out_order_pkts);
    StatlineI("max segm size","bytes","%8lu",
	      pab->max_seg_size,
	      pba->max_seg_size);
    StatlineI("min segm size","bytes","%8lu",
	      pab->min_seg_size,
	      pba->min_seg_size);
    StatlineI("avg segm size","bytes","%8lu",
	      (int)((double)pab->data_bytes / ((double)pab->data_pkts+.001)),
	      (int)((double)pba->data_bytes / ((double)pba->data_pkts+.001)));
    StatlineI("max win adv","bytes","%8lu", pab->win_max, pba->win_max);
    StatlineI("min win adv","bytes","%8lu", pab->win_min, pba->win_min);
    StatlineI("zero win adv","","%8lu", pab->win_zero_ct, pba->win_zero_ct);
    StatlineI("avg win adv","bytes","%8lu",
	      pab->ack_pkts==0?0:pab->win_tot/pab->ack_pkts,
	      pba->ack_pkts==0?0:pba->win_tot/pba->ack_pkts);


    /* do the throughput calcs */
    etime_float = (double) etime / 1000000.0;
    StatLineF("throughput","Bps","%8.0f",
	      (double) (pab->data_bytes-pab->rexmit_bytes) / etime_float,
	      (double) (pba->data_bytes-pba->rexmit_bytes) / etime_float);

    if (print_rtt) {
	fprintf(stdout,"\n");
	StatlineI("RTT samples","","%8lu", pab->rtt_count, pba->rtt_count);
	StatLineF("RTT min","ms","%8.1f",
		  (double)pab->rtt_min/1000.0,
		  (double)pba->rtt_min/1000.0);
	StatLineF("RTT max","ms","%8.1f",
		  (double)pab->rtt_max/1000.0,
		  (double)pba->rtt_max/1000.0);
	StatLineF("RTT avg","ms","%8.1f",
		  Average(pab->rtt_sum, pab->rtt_count) / 1000.0,
		  Average(pba->rtt_sum, pba->rtt_count) / 1000.0);
	StatLineF("RTT stdev","ms","%8.1f",
		  Stdev(pab->rtt_sum, pab->rtt_sum2, pab->rtt_count) / 1000.0,
		  Stdev(pba->rtt_sum, pba->rtt_sum2, pba->rtt_count) / 1000.0);

	if (pab->rtt_amback || pba->rtt_amback) {
	    fprintf(stdout, "\
\t  For the following 5 RTT statistics, only ACKs for
\t  multiply-transmitted segments (ambiguous ACKs) were
\t  considered.  Times are taken from the last instance
\t  of a segment.
");
	    StatlineI("ambiguous acks","","%8lu",
		      pab->rtt_amback, pba->rtt_amback);
	    StatLineF("RTT min (last)","ms","%8.1f",
		      (double)pab->rtt_min_last/1000.0,
		      (double)pba->rtt_min_last/1000.0);
	    StatLineF("RTT max (last)","ms","%8.1f",
		      (double)pab->rtt_max_last/1000.0,
		      (double)pba->rtt_max_last/1000.0);
	    StatLineF("RTT avg (last)","ms","%8.1f",
		      Average(pab->rtt_sum_last, pab->rtt_count_last) / 1000.0,
		      Average(pba->rtt_sum_last, pba->rtt_count_last) / 1000.0);
	    StatLineF("RTT sdv (last)","ms","%8.1f",
		      Stdev(pab->rtt_sum_last, pab->rtt_sum2_last, pab->rtt_count_last) / 1000.0,
		      Stdev(pba->rtt_sum_last, pba->rtt_sum2_last, pba->rtt_count_last) / 1000.0);

	}
	StatlineI("segs cum acked","","%8lu",
		  pab->rtt_cumack, pba->rtt_cumack);
	StatlineI("duplicate acks","","%8lu",
		  pab->rtt_dupack, pba->rtt_dupack);
	if (debug)
	    StatlineI("unknown acks:","","%8lu",
		      pab->rtt_unkack, pba->rtt_unkack);
	StatlineI("max # retrans","","%8lu",
		  pab->retr_max, pba->retr_max);
	StatLineF("min retr time","ms","%8.1f",
		  (double)((double)pab->retr_min_tm/1000.0),
		  (double)((double)pba->retr_min_tm/1000.0));
	StatLineF("max retr time","ms","%8.1f",
		  (double)((double)pab->retr_max_tm/1000.0),
		  (double)((double)pba->retr_max_tm/1000.0));
	StatLineF("avg retr time","ms","%8.1f",
		  Average(pab->retr_tm_sum, pab->retr_tm_count) / 1000.0,
		  Average(pba->retr_tm_sum, pba->retr_tm_count) / 1000.0);
	StatlineI("sdv retr time","ms","%8.1f",
		  Stdev(pab->retr_tm_sum, pab->retr_tm_sum2,
			pab->retr_tm_count) / 1000.0,
		  Stdev(pba->retr_tm_sum, pba->retr_tm_sum2,
			pba->retr_tm_count) / 1000.0);
    }
}


static void
StatlineI(
    char *label,
    char *units,
    char *format,
    u_long argleft,
    u_long argright)
{
    StatLineField(label,units,format,argleft,0);
    StatLineField(label,units,format,argright,1);
}


static void
StatLineF(
    char *label,
    char *units,
    char *format,
    double argleft,
    double argright)
{
    StatLineFieldF(label,units,format,argleft,0);
    StatLineFieldF(label,units,format,argright,1);
}




static void
StatLineField(
    char *label,
    char *units,
    char *format,
    u_long arg,
    int	f_rightside)
{
    char valbuf[20];
    
    /* determine the value to print */
    sprintf(valbuf,format,arg);

    /* print the field */
    printf("     ");
    StatLineOne(label, units, valbuf);
    if (f_rightside)
	printf("\n");
}


static void
StatLineFieldF(
    char *label,
    char *units,
    char *format,
    double arg,
    int	f_rightside)
{
    int printable;
    char valbuf[20];

    /* see if the float argument is printable */
    printable = finite(arg);
    
    /* determine the value to print */
    if (printable)
	sprintf(valbuf,format,arg);

    /* print the field */
    printf("     ");
    if (printable)
	StatLineOne(label, units, valbuf);
    else
	StatLineOne(label, "", "NA");
    if (f_rightside)
	printf("\n");
}


static void
StatLineOne(
    char *label,
    char *units,
    char *value)
{
    char labbuf[20];
    
    /* format the label */
    sprintf(labbuf, "%s:", label);

    /* print the field */
    printf("%-18s %9s %-5s", labbuf, value, units);
}
