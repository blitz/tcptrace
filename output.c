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
#include "gcache.h"


/* local routines */
static u_int SynCount(tcp_pair *);
static u_int FinCount(tcp_pair *);
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

    sprintf(infobuf,"%s - %s (%s2%s)",
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

    fprintf(stdout,"\thost %-4s      %s\n",
	    (sprintf(bufl,"%s:", host1),bufl), ptp->a_endpoint);
    fprintf(stdout,"\thost %-4s      %s\n",
	    (sprintf(bufl,"%s:", host2),bufl), ptp->b_endpoint);
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
    etime_secs = etime / 1000000.0;
    etime_usecs = 1000000 * (etime/1000000.0 - (double)etime_secs);
    fprintf(stdout,"\telapsed time:  %s\n", elapsed2str(etime));

#ifdef HAVE_LONG_LONG
    fprintf(stdout,"\ttotal packets: %llu\n", ptp->packets);
#else  /* HAVE_LONG_LONG */
    fprintf(stdout,"\ttotal packets: %lu\n", ptp->packets);
#endif  /* HAVE_LONG_LONG */

    fprintf(stdout,"\tfilename:      %s\n", ptp->filename);

    fprintf(stdout,"   %s->%s:			      %s->%s:\n",
	    host1,host2,host2,host1);

    StatLineI("total packets","", pab->packets, pba->packets);
    if (pab->reset_count || pba->reset_count)
	StatLineI("resets sent","", pab->reset_count, pba->reset_count);
    StatLineI("ack pkts sent","", pab->ack_pkts, pba->ack_pkts);
    StatLineI("pure acks sent","", pab->pureack_pkts, pba->pureack_pkts);
    StatLineI("unique bytes sent","",
	      pab->data_bytes-pab->rexmit_bytes,
	      pba->data_bytes-pba->rexmit_bytes);
#ifdef OLD
    StatLineI("unique packets","",
	      pab->data_pkts-pab->rexmit_pkts,
	      pba->data_pkts-pba->rexmit_pkts);
#endif /* OLD */
    StatLineI("actual data pkts","", pab->data_pkts, pba->data_pkts);
    StatLineI("actual data bytes","", pab->data_bytes, pba->data_bytes);
    StatLineI("rexmt data pkts","", pab->rexmit_pkts, pba->rexmit_pkts);
    StatLineI("rexmt data bytes","",
	      pab->rexmit_bytes, pba->rexmit_bytes);
    StatLineI("outoforder pkts","",
	      pab->out_order_pkts, pba->out_order_pkts);
    StatLineI("pushed data pkts","", pab->data_pkts_push, pba->data_pkts_push);
    StatLineP("SYN/FIN pkts sent","","%s",
	      (sprintf(bufl,"%d/%d",
		       pab->syn_count, pab->fin_count),bufl),
	      (sprintf(bufr,"%d/%d",
		       pba->syn_count, pba->fin_count),bufr));
    if (pab->f1323_ws || pba->f1323_ws || pab->f1323_ts || pba->f1323_ts) {
	StatLineP("req 1323 ws/ts","","%s",
		  (sprintf(bufl,"%c/%c",
		      pab->f1323_ws?'Y':'N',pab->f1323_ts?'Y':'N'),bufl),
		  (sprintf(bufr,"%c/%c",
		      pba->f1323_ws?'Y':'N',pba->f1323_ts?'Y':'N'),bufr));
    }
    if (pab->f1323_ws || pba->f1323_ws) {
	StatLineI("adv wind scale","",
		  (u_long)pab->window_scale, (u_long)pba->window_scale);
    }
    if (pab->fsack_req || pba->fsack_req) {
	StatLineP("req sack","","%s",
		  pab->fsack_req?"Y":"N",
		  pba->fsack_req?"Y":"N");
	StatLineI("sacks sent","",
		  pab->sacks_sent,
		  pba->sacks_sent);
    }
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
    StatLineI("avg win adv","bytes",
	      pab->ack_pkts==0?0:pab->win_tot/pab->ack_pkts,
	      pba->ack_pkts==0?0:pba->win_tot/pba->ack_pkts);
    if (print_cwin) {
	StatLineI("max cwin","bytes", pab->cwin_max, pba->cwin_max);
	StatLineI("min cwin","bytes", pab->cwin_min, pba->cwin_min);
	StatLineI("avg cwin","bytes",
		  pab->ack_pkts==0?0:pab->cwin_tot/pab->ack_pkts,
		  pba->ack_pkts==0?0:pba->cwin_tot/pba->ack_pkts);
    }
    StatLineI("initial window","bytes",
	      pab->initialwin_bytes, pba->initialwin_bytes);
    StatLineI("initial window","pkts",
	      pab->initialwin_segs, pba->initialwin_segs);


    /* compare to theoretical length of the stream (not just what
       we saw) using the SYN and FIN
       (N.B. not taking wrapped seq space into account) */
    if ((pab->syn_count > 0) && (pab->fin_count > 0) &&
	(pba->syn_count > 0) && (pba->fin_count > 0)) {
	StatLineI("ttl stream length","bytes",
		  pab->fin-pab->syn-1,
		  pba->fin-pba->syn-1);
	StatLineI("missed data","bytes",
		  pab->fin-pab->syn-1-(pab->data_bytes-pab->rexmit_bytes),
		  pba->fin-pba->syn-1-(pba->data_bytes-pba->rexmit_bytes));
    } else {
	StatLineP("ttl stream length","","%s","NA","NA");
	StatLineP("missed data","","%s","NA","NA");
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

    if ((pab->num_hardware_dups != 0) || (pba->num_hardware_dups != 0)) {
	StatLineI("hardware dups","segs",
		  pab->num_hardware_dups, pba->num_hardware_dups);
	fprintf(stdout,
	       "       ** WARNING: presence of hardware duplicates makes these figures suspect!\n");
    }

    /* do the throughput calcs */
    etime /= 1000000.0;  /* convert to seconds */
    if (etime == 0.0)
	StatLineP("throughput","","%s","NA","NA");
    else
	StatLineF("throughput","Bps","%8.0f",
		  (double) (pab->data_bytes-pab->rexmit_bytes) / etime,
		  (double) (pba->data_bytes-pba->rexmit_bytes) / etime);

    if (print_rtt) {
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

	StatLineI("post-loss acks","",
		  pab->rtt_nosample, pba->rtt_nosample);
	if (pab->rtt_amback || pba->rtt_amback) {
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
#ifdef HAVE_LONG_LONG
	fprintf(stdout," %4llu>", pab->packets);
	fprintf(stdout," %4llu<", pba->packets);
#else /* HAVE_LONG_LONG */
	fprintf(stdout," %4lu>", pab->packets);
	fprintf(stdout," %4lu<", pba->packets);
#endif /* HAVE_LONG_LONG */
    } else {
	/* old version */
	fprintf(stdout,"%s <==> %s",
		ptp->a_endpoint,
		ptp->b_endpoint);
#ifdef HAVE_LONG_LONG
	fprintf(stdout,"  %s2%s:%llu",
#else /* HAVE_LONG_LONG */
	fprintf(stdout,"  %s2%s:%lu",
#endif /* HAVE_LONG_LONG */
		pab->host_letter,
		pba->host_letter,
		pab->packets);
#ifdef HAVE_LONG_LONG
	fprintf(stdout,"  %s2%s:%llu",
#else /* HAVE_LONG_LONG */
	fprintf(stdout,"  %s2%s:%lu",
#endif /* HAVE_LONG_LONG */
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
	    (sprintf(bufl,"%s:", host1),bufl), pup->a_endpoint);
    fprintf(stdout,"\thost %-4s      %s\n",
	    (sprintf(bufl,"%s:", host2),bufl), pup->b_endpoint);
    fprintf(stdout,"\n");

    fprintf(stdout,"\tfirst packet:  %s\n", ts2ascii(&pup->first_time));
    fprintf(stdout,"\tlast packet:   %s\n", ts2ascii(&pup->last_time));

    etime = elapsed(pup->first_time,pup->last_time);
    etime_secs = etime / 1000000.0;
    etime_usecs = 1000000 * (etime/1000000.0 - (double)etime_secs);
    fprintf(stdout,"\telapsed time:  %s\n", elapsed2str(etime));

#ifdef HAVE_LONG_LONG
    fprintf(stdout,"\ttotal packets: %llu\n", pup->packets);
#else  /* HAVE_LONG_LONG */
    fprintf(stdout,"\ttotal packets: %lu\n", pup->packets);
#endif  /* HAVE_LONG_LONG */

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
    char *format = "%8llu";
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
    char valbuf[20];
    
    /* determine the value to print */
    sprintf(valbuf,format,arg);

    /* print the field */
    printf("     ");
    StatLineOne(label, units, valbuf);
    if (f_rightside)
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


char *
elapsed2str(
    double etime)
{
    static char buf[80];
    u_long etime_secs;
    u_long etime_usecs;

    etime_secs = etime / 1000000.0;
    etime_usecs = 1000000 * (etime/1000000.0 - (double)etime_secs);
    sprintf(buf,"%lu:%02lu:%02lu.%06lu",
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
#ifdef HAVE_LONG_LONG
    fprintf(stdout," %4llu>", pab->packets);
    fprintf(stdout," %4llu<", pba->packets);
#else /* HAVE_LONG_LONG */
    fprintf(stdout," %4lu>", pab->packets);
    fprintf(stdout," %4lu<", pba->packets);
#endif /* HAVE_LONG_LONG */

    fprintf(stdout,"\n");
}


static char *
UDPFormatBrief(
    udp_pair *pup)
{
    ucb *pab = &pup->a2b;
    ucb *pba = &pup->b2a;
    static char infobuf[100];

    sprintf(infobuf,"%s - %s (%s2%s)",
	    pup->a_endpoint, pup->b_endpoint,
	    pab->host_letter, pba->host_letter);
    return(infobuf);
}
