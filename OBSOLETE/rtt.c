/*
 * Copyright (c) 1994, 1995, 1996
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
    "@(#)Copyright (c) 1996\nOhio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


/* 
 * rtt.c - Round Trip Timing Routines
 */

#include "tcptrace.h"


/* local routines */
static seg_rec *newseg(void);
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
newseg(void)
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



