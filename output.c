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
#include "gcache.h"


/* local routines */
static double Average(double, int);
static double Stdev(double, double, int);
static void StatLineP(char *, char *, char *, void *, void *);
static void StatLineI_L(char *, char *, u_long, u_long);
#ifdef HAVE_LONG_LONG
static void StatLineI_LL(char *, char *, u_llong, u_llong);
static void StatLineFieldL(char *, char *, char *, u_llong, int);
#endif  /* HAVE_LONG_LONG */
static void StatLineF(char *, char *, char *, double, double);
static void StatLineField(char *, char *, char *, u_long, int);
static void StatLineFieldF(char *, char *, char *, double, int);
static void StatLineOne(char *, char *, char *);
static char *FormatBrief(tcp_pair *ptp);
static char *UDPFormatBrief(udp_pair *pup);

/* locally global variables*/
static u_int sv_print_count    = 0;
static u_int sv_expected_count = 0;

/* global variables */
char *sp;  /* Separator used for long output with <SP>-separated-values */

/* to support some of the counters being long long on some platforms, use this */
/* macro... */
#ifdef HAVE_LONG_LONG
#define StatLineI(label,units,ul1,ul2)  \
(sizeof((ul1)) == SIZEOF_UNSIGNED_LONG_LONG_INT)?\
  StatLineI_LL((label),(units),(ul1),(ul2)):\
  StatLineI_L ((label),(units),(ul1),(ul2))
#else /* HAVE_LONG_LONG */
#define StatLineI StatLineI_L
#endif /* HAVE_LONG_LONG */

/* Size of header for comma-separated-values or tab-separated-values
 * The size is actually (SV_HEADER_COLUMN_COUNT - 1) & (SV__RTT_HEADER_COLUMN_COUNT - 1)
 * since there is a NULL at the end.
 * NOTE: If the exact number of fields are not printed for each connection,
 * the program will print out an error messages. This is a precautionary measure.
 */
#define SV_HEADER_COLUMN_COUNT 88
#define SV_RTT_HEADER_COLUMN_COUNT 51

u_int
SynCount(
    tcp_pair *ptp)
{
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;

    return(((pab->syn_count >= 1)?1:0) +
	   ((pba->syn_count >= 1)?1:0));
}



u_int
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
    double retval;

    if (n<=2)
	return(0.0);

    term1 = sum2;
    term2 = (sum * sum) / (double)n;
    term = term1-term2;
    term /= (double)(n-1);
    retval = sqrt(term);

/*     printf("Stdev(%f,%f,%d) is %f\n", sum,sum2,n,retval); */

    return(retval);
}





static char *
FormatBrief(
    tcp_pair *ptp)
{
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;
    static char infobuf[100];

    snprintf(infobuf,sizeof(infobuf),"%s - %s (%s2%s)",
	    ptp->a_endpoint, ptp->b_endpoint,
	    pab->host_letter, pba->host_letter);
    return(infobuf);
}





void
PrintTrace(
    tcp_pair *ptp)
{
    double etime;
    u_long etime_secs;
    u_long etime_usecs;
    double etime_data1;
    double etime_data2;
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;
    char *host1 = pab->host_letter;
    char *host2 = pba->host_letter;
    char bufl[40],bufr[40];
   
    /* counters to use for seq. space wrap around calculations
     */
    u_llong stream_length_pab=0, stream_length_pba=0;
    u_long pab_last, pba_last;

   /* Reset the counter for each connection */
   sv_print_count = 1; /* The first field (conn_#) gets printed in trace.c */
   

    /* calculate elapsed time */
    etime = elapsed(ptp->first_time,ptp->last_time);
    etime_secs = etime / 1000000.0;
    etime_usecs = 1000000 * (etime/1000000.0 - (double)etime_secs);

    /* Check if comma-separated-values or tab-separated-values
     * has been requested.
     */ 
   if(csv || tsv || (sv != NULL)) {
       fprintf(stdout,"%s%s%s%s%s%s%s%s",
	       ptp->a_hostname, sp, ptp->b_hostname, sp,
	       ptp->a_portname, sp, ptp->b_portname, sp);
       sv_print_count += 4;
       /* Print the start and end times. In other words,
	* print the time of the first and the last packet
	*/ 
       fprintf(stdout,"%lu.%lu %s %lu.%lu %s",
	       ptp->first_time.tv_sec, ptp->first_time.tv_usec, sp,
	       ptp->last_time.tv_sec,  ptp->last_time.tv_usec,  sp);
       sv_print_count += 2;      
    }
    else {
       fprintf(stdout,"\thost %-4s      %s\n",
	       (snprintf(bufl,sizeof(bufl),"%s:", host1),bufl), ptp->a_endpoint);
       fprintf(stdout,"\thost %-4s      %s\n",
	       (snprintf(bufl,sizeof(bufl),"%s:", host2),bufl), ptp->b_endpoint);
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
       
       fprintf(stdout,"\telapsed time:  %s\n", elapsed2str(etime));
       
       fprintf(stdout,"\ttotal packets: %" FS_ULL "\n", ptp->packets);
       
       fprintf(stdout,"\tfilename:      %s\n", ptp->filename);
       
       fprintf(stdout,"   %s->%s:			      %s->%s:\n",
	       host1,host2,host2,host1);
    }
   
    StatLineI("total packets","", pab->packets, pba->packets);
    if (pab->reset_count || pba->reset_count || csv || tsv || (sv != NULL))
	StatLineI("resets sent","", pab->reset_count, pba->reset_count);
    StatLineI("ack pkts sent","", pab->ack_pkts, pba->ack_pkts);
    StatLineI("pure acks sent","", pab->pureack_pkts, pba->pureack_pkts);
    StatLineI("sack pkts sent","", pab->num_sacks, pba->num_sacks);
    StatLineI("max sack blks/ack","", pab->max_sack_blocks, pba->max_sack_blocks);
    StatLineI("unique bytes sent","",
	      pab->unique_bytes, pba->unique_bytes);
    StatLineI("actual data pkts","", pab->data_pkts, pba->data_pkts);
    StatLineI("actual data bytes","", pab->data_bytes, pba->data_bytes);
    StatLineI("rexmt data pkts","", pab->rexmit_pkts, pba->rexmit_pkts);
    StatLineI("rexmt data bytes","",
	      pab->rexmit_bytes, pba->rexmit_bytes);
    StatLineI("zwnd probe pkts","", 
		  pab->num_zwnd_probes, pba->num_zwnd_probes);
    StatLineI("zwnd probe bytes","",
	      pab->zwnd_probe_bytes, pba->zwnd_probe_bytes);
    StatLineI("outoforder pkts","",
	      pab->out_order_pkts, pba->out_order_pkts);
    StatLineI("pushed data pkts","", pab->data_pkts_push, pba->data_pkts_push);
    StatLineP("SYN/FIN pkts sent","","%s",
	      (snprintf(bufl,sizeof(bufl),"%d/%d",
		       pab->syn_count, pab->fin_count),bufl),
	      (snprintf(bufr,sizeof(bufr),"%d/%d",
		       pba->syn_count, pba->fin_count),bufr));
    if (pab->f1323_ws || pba->f1323_ws || pab->f1323_ts || pba->f1323_ts || csv || tsv || (sv != NULL)) {
	StatLineP("req 1323 ws/ts","","%s",
		  (snprintf(bufl,sizeof(bufl),"%c/%c",
		      pab->f1323_ws?'Y':'N',pab->f1323_ts?'Y':'N'),bufl),
		  (snprintf(bufr,sizeof(bufr),"%c/%c",
		      pba->f1323_ws?'Y':'N',pba->f1323_ts?'Y':'N'),bufr));
    }
    if (pab->f1323_ws || pba->f1323_ws || csv || tsv || (sv != NULL)) {
	StatLineI("adv wind scale","",
		  (u_long)pab->window_scale, (u_long)pba->window_scale);
    }
    if (pab->fsack_req || pba->fsack_req || csv || tsv || (sv != NULL)) {
	StatLineP("req sack","","%s",
		  pab->fsack_req?"Y":"N",
		  pba->fsack_req?"Y":"N");
	StatLineI("sacks sent","",
		  pab->sacks_sent,
		  pba->sacks_sent);
    }
    StatLineI("urgent data pkts", "pkts",
	      pab->urg_data_pkts,
	      pba->urg_data_pkts);
    StatLineI("urgent data bytes", "bytes",
	      pab->urg_data_bytes,
	      pba->urg_data_bytes);
    StatLineI("mss requested","bytes", pab->mss, pba->mss);
    StatLineI("max segm size","bytes",
	      pab->max_seg_size,
	      pba->max_seg_size);
    StatLineI("min segm size","bytes",
	      pab->min_seg_size,
	      pba->min_seg_size);
    StatLineI("avg segm size","bytes",
	      (int)((double)pab->data_bytes / ((double)pab->data_pkts+.001)),
	      (int)((double)pba->data_bytes / ((double)pba->data_pkts+.001)));
    StatLineI("max win adv","bytes", pab->win_max, pba->win_max);
    StatLineI("min win adv","bytes", pab->win_min, pba->win_min);
    StatLineI("zero win adv","times",
	      pab->win_zero_ct, pba->win_zero_ct);
    /* Changed this computation from
     *   division by pXX->ack_pkts to
     *   division by pXX->packets
     * --Avinash.
     */ 
    StatLineI("avg win adv","bytes",
	      pab->ack_pkts==0?0:pab->win_tot/pab->packets,
	      pba->ack_pkts==0?0:pba->win_tot/pba->packets);
    if (print_owin) {
	StatLineI("max owin","bytes", pab->owin_max, pba->owin_max);
	StatLineI("min non-zero owin","bytes", pab->owin_min, pba->owin_min);
	StatLineI("avg owin","bytes",
		  pab->owin_count==0?0:pab->owin_tot/pab->owin_count,
		  pba->owin_count==0?0:pba->owin_tot/pba->owin_count);
	if (etime == 0.0) {
		StatLineP("wavg owin", "", "%s", "NA", "NA");	
	}
	else {
		StatLineI("wavg owin","bytes", 
			  (u_llong)(pab->owin_wavg/((double)etime/1000000)), 
		  	  (u_llong)(pba->owin_wavg/((double)etime/1000000)));
   	} 
    }
    StatLineI("initial window","bytes",
	      pab->initialwin_bytes, pba->initialwin_bytes);
    StatLineI("initial window","pkts",
	      pab->initialwin_segs, pba->initialwin_segs);

    /* compare to theoretical length of the stream (not just what
       we saw) using the SYN and FIN
     * Seq. Space wrap around calculations:
     * Calculate stream length using last_seq_num seen, first_seq_num
     * seen and wrap_count.
     * first_seq_num = syn
     * If reset_set, last_seq_num = latest_seq
     *          else last_seq_num = fin
     */
    
    pab_last = (pab->reset_count>0)?pab->latest_seq:pab->fin;
    
    pba_last = (pba->reset_count>0)?pba->latest_seq:pba->fin;
    
    /* calculating stream length for direction pab */
    if ((pab->syn_count > 0) && (pab->fin_count > 0)) {
	if (pab->seq_wrap_count > 0) {
	    if (pab_last > pab->syn) {
		stream_length_pab = pab_last + (MAX_32 * pab->seq_wrap_count) - pab->syn - 1;
	    }
	    else {
		stream_length_pab = pab_last + (MAX_32 * (pab->seq_wrap_count+1)) - pab->syn - 1;
	    }
	}
	else {
	    if (pab_last > pab->syn) {
		stream_length_pab = pab_last - pab->syn - 1;
	    }
	    else {
		stream_length_pab = MAX_32 + pab_last - pab->syn - 1;
	    }
	}
    }

    /* calculating stream length for direction pba */
    if ((pba->syn_count > 0) && (pba->fin_count > 0)) {
	if (pba->seq_wrap_count > 0) {
	    if (pba_last > pba->syn) {
		stream_length_pba = pba_last + (MAX_32 * pba->seq_wrap_count) - pba->syn - 1;
	    }
	    else {
		stream_length_pba = pba_last + (MAX_32 * (pba->seq_wrap_count+1)) - pba->syn - 1;
	    }
	}
	else {
	    if (pba_last > pba->syn) {
		stream_length_pba = pba_last - pba->syn - 1;
	    }
	    else {
		stream_length_pba = MAX_32 + pba_last - pba->syn - 1;
	    }
	}
    }

    /* print out values */
    if ((pab->fin_count > 0) && (pab->syn_count > 0)) {
	char *format = "%8" FS_ULL;
	StatLineFieldL("ttl stream length", "bytes", format, stream_length_pab, 0);
    }
    else {
	StatLineField("ttl stream length", "", "%s", (u_long)"NA", 0);
    }
    if ((pba->fin_count > 0) && (pba->syn_count > 0)) {
	char *format = "%8" FS_ULL;
	StatLineFieldL("ttl stream length", "bytes", format, stream_length_pba, 1);
    }
    else {
	StatLineField("ttl stream length", "", "%s", (u_long)"NA", 1);
    }

    if ((pab->fin_count > 0) && (pab->syn_count > 0)) {
	char *format = "%8" FS_ULL;
	StatLineFieldL("missed data", "bytes", format, (stream_length_pab - pab->unique_bytes), 0);
    }
    else {
	StatLineField("missed data", "", "%s", (u_long)"NA", 0);
    }
    if ((pba->fin_count > 0) && (pba->syn_count > 0)) {
	char *format = "%8" FS_ULL;
	StatLineFieldL("missed data", "bytes", format, (stream_length_pba - pba->unique_bytes), 1);
    }
    else {
	StatLineField("missed data", "", "%s", (u_long)"NA", 1);
    }
    
    /* tell how much data was NOT captured in the files */
    StatLineI("truncated data","bytes",
	      pab->trunc_bytes, pba->trunc_bytes);
    StatLineI("truncated packets","pkts",
	      pab->trunc_segs, pba->trunc_segs);

    /* stats on just the data */
    etime_data1 = elapsed(pab->first_data_time,
			  pab->last_data_time); /* in usecs */
    etime_data2 = elapsed(pba->first_data_time,
			  pba->last_data_time); /* in usecs */
    /* fix from Rob Austein */
    StatLineF("data xmit time","secs","%7.3f",
	      etime_data1 / 1000000.0,
	      etime_data2 / 1000000.0);
    StatLineP("idletime max","ms","%s",
	      ZERO_TIME(&pab->last_time)?"NA":
	      (snprintf(bufl,sizeof(bufl),"%8.1f",(double)pab->idle_max/1000.0),bufl),
	      ZERO_TIME(&pba->last_time)?"NA":
	      (snprintf(bufr,sizeof(bufr),"%8.1f",(double)pba->idle_max/1000.0),bufr));

    if ((pab->num_hardware_dups != 0) || (pba->num_hardware_dups != 0)  || csv || tsv || (sv != NULL)) {
	StatLineI("hardware dups","segs",
		  pab->num_hardware_dups, pba->num_hardware_dups);

        if(!(csv || tsv || (sv != NULL)))       
	  fprintf(stdout,
		  "       ** WARNING: presence of hardware duplicates makes these figures suspect!\n");
    }

    /* do the throughput calcs */
    etime /= 1000000.0;  /* convert to seconds */
    if (etime == 0.0)
	StatLineP("throughput","","%s","NA","NA");
    else
	StatLineF("throughput","Bps","%8.0f",
		  (double) (pab->unique_bytes) / etime,
		  (double) (pba->unique_bytes) / etime);

    if (print_rtt) {
        if(!(csv || tsv || (sv != NULL)))
	  fprintf(stdout,"\n");
	StatLineI("RTT samples","", pab->rtt_count, pba->rtt_count);
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
        if(!(csv || tsv || (sv != NULL)))
	  fprintf(stdout,"\n");
	StatLineF("RTT from 3WHS","ms","%8.1f",
		  (double)pab->rtt_3WHS/1000.0,
		  (double)pba->rtt_3WHS/1000.0);
        if(!(csv || tsv || (sv != NULL)))
	  fprintf(stdout,"\n");
	StatLineI("RTT full_sz smpls","", 
		  pab->rtt_full_count, pba->rtt_full_count);
	StatLineF("RTT full_sz min","ms","%8.1f",
		  (double)pab->rtt_full_min/1000.0,
		  (double)pba->rtt_full_min/1000.0);
	StatLineF("RTT full_sz max","ms","%8.1f",
		  (double)pab->rtt_full_max/1000.0,
		  (double)pba->rtt_full_max/1000.0);
	StatLineF("RTT full_sz avg","ms","%8.1f",
		  Average(pab->rtt_full_sum, pab->rtt_full_count) / 1000.0,
		  Average(pba->rtt_full_sum, pba->rtt_full_count) / 1000.0);
	StatLineF("RTT full_sz stdev","ms","%8.1f",
		  Stdev(pab->rtt_full_sum, pab->rtt_full_sum2, pab->rtt_full_count) / 1000.0,
		  Stdev(pba->rtt_full_sum, pba->rtt_full_sum2, pba->rtt_full_count) / 1000.0);
        if(!(csv || tsv || (sv != NULL)))
	  fprintf(stdout,"\n");
	StatLineI("post-loss acks","",
		  pab->rtt_nosample, pba->rtt_nosample);
	if (pab->rtt_amback || pba->rtt_amback || csv || tsv || (sv != NULL)) {
	   if(!(csv || tsv || (sv != NULL)))
	     fprintf(stdout, "\
\t  For the following 5 RTT statistics, only ACKs for\n\
\t  multiply-transmitted segments (ambiguous ACKs) were\n\
\t  considered.  Times are taken from the last instance\n\
\t  of a segment.\n\
");
	    StatLineI("ambiguous acks","",
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
	StatLineI("segs cum acked","",
		  pab->rtt_cumack, pba->rtt_cumack);
	StatLineI("duplicate acks","",
		  pab->rtt_dupack, pba->rtt_dupack);
	StatLineI("triple dupacks","",
		  pab->rtt_triple_dupack, pba->rtt_triple_dupack);
	if (debug)
	    StatLineI("unknown acks:","",
		      pab->rtt_unkack, pba->rtt_unkack);
	StatLineI("max # retrans","",
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
	StatLineF("sdv retr time","ms","%8.1f",
		  Stdev(pab->retr_tm_sum, pab->retr_tm_sum2,
			pab->retr_tm_count) / 1000.0,
		  Stdev(pba->retr_tm_sum, pba->retr_tm_sum2,
			pba->retr_tm_count) / 1000.0);
    }
   
   if(csv || tsv || (sv != NULL)) {
      printf("\n");
      /* Error checking: print an error message if the count of printed fields
       * doesn't correspond to the actual fields expected.
       */
      if(sv_print_count != sv_expected_count) {
	 fprintf(stderr, "output.c: Count of printed fields does not correspond to count of header fields for long output with comma/tab/<SP>-separated values.\n");
	 exit(-1);
      }
   }
}

void
PrintBrief(
    tcp_pair *ptp)
{
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;
    static int max_width = -1;

    /* determine the maximum connection name width to make it nice */
    if (max_width == -1) {
	int ix;
	int len;
	tcp_pair *tmp_ptp;
	
	for (ix = 0; ix <= num_tcp_pairs; ++ix) {
	    tmp_ptp = ttp[ix];
	    if (tmp_ptp->ignore_pair)
		continue;
	    
	    len = strlen(FormatBrief(tmp_ptp));
	    if (len > max_width)
		max_width = len;
	}
	if (debug > 2)
	    fprintf(stderr,"Max name width: %d\n", max_width);
    }


    if (TRUE) {
	/* new version */
	fprintf(stdout,"%*s", -max_width, FormatBrief(ptp));

	fprintf(stdout," %4" FS_ULL ">", pab->packets);
	fprintf(stdout," %4" FS_ULL "<", pba->packets);

    } else {
	/* old version */
	fprintf(stdout,"%s <==> %s",
		ptp->a_endpoint,
		ptp->b_endpoint);

	fprintf(stdout,"  %s2%s:%"FS_ULL,
		pab->host_letter,
		pba->host_letter,
		pab->packets);

	fprintf(stdout,"  %s2%s:%"FS_ULL,
		pba->host_letter,
		pab->host_letter,
		pba->packets);
    }
    if (ConnComplete(ptp))
	fprintf(stdout,"  (complete)");
    if (ConnReset(ptp))
        fprintf(stdout,"  (reset)");
    if ((ptp->a2b.packets == 0) || (ptp->b2a.packets == 0))
        fprintf(stdout,"  (unidirectional)");

    fprintf(stdout,"\n");

    /* warning for hardware duplicates */
    if (pab->num_hardware_dups != 0) {
	fprintf(stdout,
		"    ** Warning, %s2%s: detected %lu hardware duplicate(s) (same seq # and IP ID)\n",
		pab->host_letter, pba->host_letter,
		pab->num_hardware_dups);
    }
    if (pba->num_hardware_dups != 0) {
	fprintf(stdout,
		"    ** Warning, %s2%s: detected %lu hardware duplicate(s) (same seq # and IP ID)\n",
		pba->host_letter, pab->host_letter,
		pba->num_hardware_dups);
    }
}




void
UDPPrintTrace(
    udp_pair *pup)
{
    double etime;
    u_long etime_secs;
    u_long etime_usecs;
    ucb *pab = &pup->a2b;
    ucb *pba = &pup->b2a;
    char *host1 = pab->host_letter;
    char *host2 = pba->host_letter;
    char bufl[40];

    fprintf(stdout,"\thost %-4s      %s\n",
	    (snprintf(bufl,sizeof(bufl),"%s:", host1),bufl), pup->a_endpoint);
    fprintf(stdout,"\thost %-4s      %s\n",
	    (snprintf(bufl,sizeof(bufl),"%s:", host2),bufl), pup->b_endpoint);
    fprintf(stdout,"\n");

    fprintf(stdout,"\tfirst packet:  %s\n", ts2ascii(&pup->first_time));
    fprintf(stdout,"\tlast packet:   %s\n", ts2ascii(&pup->last_time));

    etime = elapsed(pup->first_time,pup->last_time);
    etime_secs = etime / 1000000.0;
    etime_usecs = 1000000 * (etime/1000000.0 - (double)etime_secs);
    fprintf(stdout,"\telapsed time:  %s\n", elapsed2str(etime));

    fprintf(stdout,"\ttotal packets: %" FS_ULL "\n", pup->packets);

    fprintf(stdout,"\tfilename:      %s\n", pup->filename);

    fprintf(stdout,"   %s->%s:			      %s->%s:\n",
	    host1,host2,host2,host1);

    StatLineI("total packets","", pab->packets, pba->packets);
    StatLineI("data bytes sent","",
	      pab->data_bytes, pba->data_bytes);

    /* do the throughput calcs */
    etime /= 1000000.0;  /* convert to seconds */
    if (etime == 0.0)
	StatLineP("throughput","","%s","NA","NA");
    else
	StatLineF("throughput","Bps","%8.0f",
		  (double) (pab->data_bytes) / etime,
		  (double) (pba->data_bytes) / etime);
}


/* with pointer args */
static void
StatLineP(
    char *label,
    char *units,
    char *format,
    void *argleft,
    void *argright)
{
    StatLineField(label,units,format,(u_long)argleft,0);
    StatLineField(label,units,format,(u_long)argright,1);
}


/* with u_long args */
static void
StatLineI_L(
    char *label,
    char *units,
    u_long argleft,
    u_long argright)
{
    char *format = "%8lu";
    StatLineField(label,units,format,argleft,0);
    StatLineField(label,units,format,argright,1);
}


#ifdef HAVE_LONG_LONG
/* with u_llong (long long) args, if supported */
static void
StatLineI_LL(
    char *label,
    char *units,
    u_llong argleft,
    u_llong argright)
{
    char *format = "%8" FS_ULL;
    StatLineFieldL(label,units,format,argleft,0);
    StatLineFieldL(label,units,format,argright,1);
}

static void
StatLineFieldL(
    char *label,
    char *units,
    char *format,
    u_llong arg,
    int	f_rightside)
{
    /* bug fix: Theo Snelleman */
    /* "The biggest number possible is 18446744073709551615 (20 digits) and
        is too big for valbuf[20] ('\0' is the 21th character)." */
    /* it was originally an array of [20] */
    char valbuf[21];
    
    /* determine the value to print */
    snprintf(valbuf,sizeof(valbuf),format,arg);

    /* print the field */
    if(!(csv || tsv || (sv != NULL)))
     printf("     ");
    StatLineOne(label, units, valbuf);
    if (f_rightside && !(csv || tsv || (sv != NULL))) 
	printf("\n");
}
#endif /* HAVE_LONG_LONG */


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
    snprintf(valbuf,sizeof(valbuf),format,arg);

    /* print the field */
    if(!(csv || tsv || (sv != NULL)))
     printf("     ");
    StatLineOne(label, units, valbuf);
    if (f_rightside && !(csv || tsv || (sv != NULL)))
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
	snprintf(valbuf,sizeof(valbuf),format,arg);

    /* print the field */
    if(!(csv || tsv || (sv != NULL)))
     printf("     ");
    if (printable)
	StatLineOne(label, units, valbuf);
    else
	StatLineOne(label, "", "NA");
    if (f_rightside && !(csv || tsv || (sv != NULL)))
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
    snprintf(labbuf,sizeof(labbuf), "%s:", label);

    /* print the field */
    if(csv || tsv || (sv != NULL)) {
       printf("%15s%s", value, sp);
       /* Count the fields printed until this point. Used as a guard with the
	* <SP>-separated-values option to ensure correct alignment of headers
	* and field values.
	*/
       sv_print_count++;
    }   
    else 
     printf("%-18s %9s %-5s", labbuf, value, units);
}


char *
elapsed2str(
    double etime)
{
    static char buf[80];
    u_long etime_secs;
    u_long etime_usecs;

    etime_secs = etime / 1000000.0;
    etime_usecs = 1000000 * (etime/1000000.0 - (double)etime_secs);
    snprintf(buf,sizeof(buf),"%lu:%02lu:%02lu.%06lu",
	    etime_secs / (60 * 60),
	    etime_secs % (60 * 60) / 60,
	    (etime_secs % (60 * 60)) % 60,
	    etime_usecs);
    return(buf);
}


void
UDPPrintBrief(
    udp_pair *pup)
{
    ucb *pab = &pup->a2b;
    ucb *pba = &pup->b2a;
    static int max_width = -1;

    /* determine the maximum connection name width to make it nice */
    if (max_width == -1) {
	int ix;
	int len;
	udp_pair *tmp_pup;
	
	for (ix = 0; ix <= num_udp_pairs; ++ix) {
	    tmp_pup = utp[ix];
	    
	    len = strlen(UDPFormatBrief(tmp_pup));
	    if (len > max_width)
		max_width = len;
	}
	if (debug > 2)
	    fprintf(stderr,"Max name width: %d\n", max_width);
    }


    /* new version */
    fprintf(stdout,"%*s", -max_width, UDPFormatBrief(pup));

    fprintf(stdout," %4" FS_ULL ">", pab->packets);
    fprintf(stdout," %4" FS_ULL "<", pba->packets);

    fprintf(stdout,"\n");
}


static char *
UDPFormatBrief(
    udp_pair *pup)
{
    ucb *pab = &pup->a2b;
    ucb *pba = &pup->b2a;
    static char infobuf[100];

    snprintf(infobuf,sizeof(infobuf),"%s - %s (%s2%s)",
	    pup->a_endpoint, pup->b_endpoint,
	    pab->host_letter, pba->host_letter);
    return(infobuf);
}


/* Print the header if comma-separated-values or tab-separated-values
 * has been requested.
 */ 
void
PrintSVHeader(
	      void)
{
   /* NOTE: If you add new headers to the tables below, make sure you update the 
    * constant defined at the top of this file to avoid getting error messages 
    * during execution. This is a safety precausion.
    */
   
   /* Headers for long output requested with comma/tab/<SP>-separated- values */
   char *svHeader[SV_HEADER_COLUMN_COUNT] = {
        "conn_#"                   ,
        "host_a"                   , "host_b",
	"port_a"                   , "port_b",
	"first_packet"             , "last_packet",
	"total_packets_a2b"        , "total_packets_b2a",
	"resets_sent_a2b"          , "resets_sent_b2a",
	"ack_pkts_sent_a2b"        , "ack_pkts_sent_b2a",
	"pure_acks_sent_a2b"       , "pure_acks_sent_b2a",
	"sack_pkts_sent_a2b"       , "sack_pkts_sent_b2a",
	"max_sack_blks/ack_a2b"    , "max_sack_blks/ack_b2a",
	"unique_bytes_sent_a2b"    , "unique_bytes_sent_b2a",
	"actual_data_pkts_a2b"     , "actual_data_pkts_b2a",
	"actual_data_bytes_a2b"    , "actual_data_bytes_b2a",
	"rexmt_data_pkts_a2b"      , "rexmt_data_pkts_b2a",
	"rexmt_data_bytes_a2b"     , "rexmt_data_bytes_b2a",
	"zwnd_probe_pkts_a2b"      , "zwnd_probe_pkts_b2a",
	"zwnd_probe_bytes_a2b"     , "zwnd_probe_bytes_b2a",
	"outoforder_pkts_a2b"      , "outoforder_pkts_b2a",
	"pushed_data_pkts_a2b"     , "pushed_data_pkts_b2a",
	"SYN/FIN_pkts_sent_a2b"    , "SYN/FIN_pkts_sent_b2a",
	"req_1323_ws/ts_a2b"       , "1323_ws/ts_b2a",
	"adv_wind_scale_a2b"       , "adv_wind_scale_b2a",
	"req_sack_a2b"             , "req_sack_b2a",
	"sacks_sent_a2b"           , "sacks_sent_b2a",
	"urgent_data_pkts_a2b"     , "urgent_data_pkts_b2a",
	"urgent_data_bytes_a2b"    , "urgent_data_bytes_b2a",
	"mss_requested_a2b"        , "mss_requested_b2a",
	"max_segm_size_a2b"        , "max_segm_size_b2a",
	"min_segm_size_a2b"        , "min_segm_size_b2a",
	"avg_segm_size_a2b"        , "avg_segm_size_b2a",
	"max_win_adv_a2b"          , "max_win_adv_b2a",
	"min_win_adv_a2b"          , "min_win_adv_b2a",
	"zero_win_adv_a2b"         , "zero_win_adv_b2a",
	"avg_win_adv_a2b"          , "avg_win_adv_b2a",
	"initial_window_bytes_a2b" , "initial_window_bytes_b2a",
	"initial_window_pkts_a2b"  , "initial_window_pkts_b2a",
	"ttl_stream_length_a2b"    , "ttl_stream_length_b2a",
	"missed_data_a2b"          , "missed_data_b2a",
	"truncated_data_a2b"       , "truncated_data_b2a",
	"truncated_packets_a2b"    , "truncated_packets_b2a",
	"data_xmit_time_a2b"       , "data_xmit_time_b2a",
	"idletime_max_a2b"         , "idletime_max_b2a",
	"hardware_dups_a2b"        , "hardware_dups_b2a",
	"throughput_a2b"           , "throughput_b2a",
	NULL
   };
   
   /* Headers for RTT, to be printed for long output requested with
    * comma/tab/<SP>-separated- values.
    */
   char *svRTTHeader[SV_RTT_HEADER_COLUMN_COUNT] = {
        "RTT_samples_a2b"       , "RTT_samples_b2a",
	"RTT_min_a2b"           , "RTT_min_b2a",
	"RTT_max_a2b"           , "RTT_max_b2a",
	"RTT_avg_a2b"           , "RTT_avg_b2a",
	"RTT_stdev_a2b"         , "RTT_stdev_b2a", 
	"RTT_from_3WHS_a2b"     , "RTT_from_3WHS_b2a",
	"RTT_full_sz_smpls_a2b" , "RTT_full_sz_smpls_b2a",
	"RTT_full_sz_min_a2b"   , "RTT_full_sz_min_b2a",
	"RTT_full_sz_max_a2b"   , "RTT_full_sz_max_b2a",
	"RTT_full_sz_avg_a2b"   , "RTT_full_sz_avg_b2a",
	"RTT full_sz_stdev_a2b" , "RTT_full_sz_stdev_b2a",
	"post-loss_acks_a2b"    , "post-loss_acks_b2a",
	"ambiguous_acks_a2b"    , "ambiguous_acks_b2a",
	"RTT_min_(last)_a2b"    , "RTT_min_(last)_b2a",
	"RTT_max_(last)_a2b"    , "RTT_max_(last)_b2a",
	"RTT_avg_(last)_a2b"    , "RTT_avg_(last)_b2a",
	"RTT_sdv_(last)_a2b"    , "RTT_sdv_(last)_b2a",
	"segs_cum_acked_a2b"    , "segs_cum_acked_b2a",
	"duplicate_acks_a2b"    , "duplicate_acks_b2a",
	"triple_dupacks_a2b"    , "triple_dupacks_b2a",
	"max_#_retrans_a2b"     , "max_#_retrans_b2a",
	"min_retr_time_a2b"     , "min_retr_time_b2a",
	"max_retr_time_a2b"     , "max_retr_time_b2a",
	"avg_retr_time_ab2"     , "avg_retr_time_b2a",
	"sdv_retr_time_a2b"     , "sdv_retr_time_b2a",
	NULL
   };
   
   /* Local Variables */
   u_int i = 0; /* Counter */ 
   
   /* Set the separator */
   if(csv || tsv) {
      /* Initialize the separator buffer */      
      sp = (char *)malloc(sizeof(char *) * 2);
      memset(sp, 0, sizeof(sp));
      /* Set it */
      if(csv)
	snprintf(sp, sizeof(sp), ",");	
      else if(tsv)
	snprintf(sp, sizeof(sp), "\t");
   }
   else if (sv != NULL)
     {
	/* Look for escape sequence and remove the extra '\',
	 * the shell puts it in there.
	 * We will do this only for the escape sequence '\t' since that is
	 * the only useful one, else the user probably meant something
	 * else and things get messy.
	 */
	if(strncmp(sv, "\\t", 2) == 0) {
	   /* Initialize the separator buffer and set it */      
	   sp = (char *)malloc(sizeof(char *) * 2);
	   memset(sp, 0, sizeof(sp));
	   snprintf(sp, sizeof(sp), "\t");
	}
	else /* Just use the string the user has provided */
	  sp = strdup(sv);
     }
   
   /* Print the column headings (the field names) */
   for(i = 0; i < SV_HEADER_COLUMN_COUNT-1; i++)
     fprintf(stdout, "%s%s", svHeader[i], sp);

   /* Print the RTT column headings (the field names) */   
   if(print_rtt)
     for(i = 0; i < SV_RTT_HEADER_COLUMN_COUNT-1; i++)
       fprintf(stdout, "%s%s", svRTTHeader[i], sp);
     
   /* Improve readability */
   fprintf(stdout, "\n\n");
   
   /* Set the number of columns expected to be printed.
    * the subtraction is to exclude the 2 NULLS, one in each array.
    */
   
   if(print_rtt)
     sv_expected_count = SV_HEADER_COLUMN_COUNT + SV_RTT_HEADER_COLUMN_COUNT - 2;
   else
     sv_expected_count = SV_HEADER_COLUMN_COUNT - 1;
}
