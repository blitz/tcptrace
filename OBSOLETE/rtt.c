/* 
 * rtt.c - Round Trip Timing Routines
 * 
 * Author:	Shawn Ostermann
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#include "tcptrace.h"


/* local routines */
static seg_rec *newseg();
static void freeseg(seg_rec *);
static void unlinkseg(seg_rec *);
static void ack_in(tcb *, struct timeval, struct tcphdr *, struct ip *);
static void seg_out(tcb *, struct timeval, struct tcphdr *, struct ip *);



void
seglist_init(
    tcb *ptcb)
{
    ptcb->seglist_head.next = &ptcb->seglist_tail;
    ptcb->seglist_tail.prev = &ptcb->seglist_head;
}



static seg_rec *
newseg()
{
    seg_rec *pnew;

    pnew = (seg_rec *) malloc(sizeof(seg_rec));
    bzero(pnew,sizeof(seg_rec));
    return(pnew);
}


static void
freeseg(
    seg_rec *pseg)
{
    free(pseg);
}


static void
unlinkseg(
    seg_rec *pseg)
{
    pseg->next->prev = pseg->prev;
    pseg->prev->next = pseg->next;
    freeseg(pseg);
}




static void
ack_in(
    tcb *ptcb,
    struct timeval time,
    struct tcphdr *ptcp,
    struct ip *pip)
{
    unsigned long etime;
    unsigned ack = ntohl(ptcp->th_ack);
    seg_rec *pseg;
    int found = 0;

    /* try to find the segment(s) acked */
    pseg = ptcb->seglist_head.next;
    while (pseg != &ptcb->seglist_tail) {
/* 	printf("Ack: %u  ackedby: %u\n", ack, pseg->ackedby); */
	if (SEQ_LESSTHAN(pseg->ackedby,ack)) {
	    /* cumulatively ACKed, just remove it */

	    ++found;
	    ++ptcb->rtt_cumack;
	    unlinkseg(pseg);
	} else if (pseg->ackedby == ack) {
	    /* specific ACK */
	    ++found;

	    /* how long did it take */
	    etime = elapsed(pseg->time,time);

	    if (pseg->retrans == 0) {
		if ((ptcb->rtt_min == 0) || (ptcb->rtt_min > etime))
		    ptcb->rtt_min = etime;

		if (ptcb->rtt_max < etime)
		    ptcb->rtt_max = etime;

		ptcb->rtt_sum += etime;
		ptcb->rtt_sum2 += (double)etime * (double)etime;
		++ptcb->rtt_count;
	    } else {
		/* retrans, can't use it */
		if ((ptcb->rtt_min_last == 0) || (ptcb->rtt_min_last > etime))
		    ptcb->rtt_min_last = etime;

		if (ptcb->rtt_max_last < etime)
		    ptcb->rtt_max_last = etime;

		ptcb->rtt_sum_last += etime;
		ptcb->rtt_sum2_last += (double)etime * (double)etime;
		++ptcb->rtt_count_last;

		++ptcb->rtt_amback;  /* ambiguous ACK */
	    }
	    
	    unlinkseg(pseg);
	}
	pseg = pseg->next;
    }

    /* did we EVER find a match */
    if (found == 0) {
	if (ack == ptcb->ptwin->ack)
	    ++ptcb->rtt_redack;
	else
	    ++ptcb->rtt_unkack;
    }
}



static void
seg_out(
    tcb *ptcb,
    struct timeval time,
    struct tcphdr *ptcp,
    struct ip *pip)
{
    unsigned long etime;
    u_long start;
    u_long len;
    seg_rec *pseg;
    
    /* find packet data */
    start = ntohl(ptcp->th_seq);

    /* calculate data length */
    len = ntohs(pip->ip_len) - (4 * pip->ip_hl) - (4 * ptcp->th_off);

    /* if it's a SYN or FIN, add one to length (for each) */
    if (SYN_SET(ptcp)) ++len;
    if (FIN_SET(ptcp)) ++len;

    /* ignore zero-data segments (no SYN or FIN either) */
    if (len == 0)
	return;

    /* see if it's already there */
    pseg = ptcb->seglist_head.next;
    while (pseg != &ptcb->seglist_tail) {
	/* currently only works for 'exact matches' */
	if (pseg->seq == start)
	    break;
	pseg = pseg->next;
    }

    if (pseg != &ptcb->seglist_tail) {
	/* it's already there, must be retrans */
	++pseg->retrans;

	etime = elapsed(pseg->time,time);
	if (pseg->retrans > ptcb->retr_max)
	    ptcb->retr_max = pseg->retrans;

	if (etime > ptcb->retr_max_tm)
	    ptcb->retr_max_tm = etime;
	if ((ptcb->retr_min_tm == 0) || (etime < ptcb->retr_min_tm))
	    ptcb->retr_min_tm = etime;

	ptcb->retr_tm_sum += etime;
	ptcb->retr_tm_sum2 += (double)etime*(double)etime;
	++ptcb->retr_tm_count;

	pseg->time = time;
    } else {
	/* not found, put at end */

	/* fill in fields in new seg entry */
	pseg = newseg();
	pseg->seq = start;
	pseg->ackedby = start + len;
	pseg->time = time;

	/* put at the end of the list */
	pseg->prev = ptcb->seglist_tail.prev;
	pseg->next = &ptcb->seglist_tail;
	ptcb->seglist_tail.prev->next = pseg;
	ptcb->seglist_tail.prev = pseg;
    }
}




void
calc_rtt(
    tcb *ptcb,
    struct timeval time,
    struct tcphdr *ptcp,
    struct ip *pip)
{
    seg_out(ptcb,time,ptcp,pip);
    ack_in(ptcb->ptwin,time,ptcp,pip);
}



#ifdef OLD
static void
print_seglist(
    tcb *ptcb)
{
    seg_rec *pseg;

    pseg = ptcb->seglist_head.next;
    while (pseg != &ptcb->seglist_tail) {
	printf("  %u %u %s\n",
	       pseg->seq,
	       pseg->ackedby,
	       ts2ascii(&pseg->time));
	pseg = pseg->next;
    }
}
#endif OLD
