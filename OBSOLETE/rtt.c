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
static void unlinkseg(seg_rec *);
static void ack_in(tcb *, struct tcphdr *, struct ip *);
static void seg_out(tcb *, struct tcphdr *, struct ip *);



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

    pnew = (seg_rec *) MallocZ(sizeof(seg_rec));

    return(pnew);
}



static void
unlinkseg(
    seg_rec *pseg)
{
    pseg->next->prev = pseg->prev;
    pseg->prev->next = pseg->next;
    free(pseg);
}




static void
ack_in(
    tcb *ptcb,
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
	    etime = elapsed(pseg->time,current_time);

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



