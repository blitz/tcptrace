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


/* 
 * rexmit.c -- Determine if a segment is a retransmit and perform RTT stats
 * 
 * Author:	Sita Menon
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 */




/*
This function rexmit() checks to see if a particular packet
is a retransmit. It returns 0 if it isn't a retransmit and 
returns the number of bytes retransmitted if it is a retransmit - 
considering the fact that it might be a partial retransmit. 
It can also keep track of packets that come out of order.
*/


#include "tcptrace.h"

/* locally global variables*/


/* local routine definitions*/
static void insert_seg_between(quadrant *, segment *, segment *, segment *);
static void collapse_quad(quadrant *);
static segment *create_seg(seqnum, seglen);
static quadrant *whichquad(seqspace *, seqnum);
static quadrant *create_quadrant(void);
static int addseg(tcb *, quadrant *, seqnum, seglen, Bool *);
static void rtt_retrans(tcb *, segment *);
static enum t_ack rtt_ackin(tcb *, segment *, Bool rexmit);
static void dump_rtt_sample(tcb *, segment *, double);
static void graph_rtt_sample(tcb *, segment *, unsigned long);



/*
 * rexmit: is the specified segment a retransmit?
 *   returns: number of retransmitted bytes in segment, 0 if not a rexmit
 *            *pout_order to to TRUE if segment is out of order
 */
int rexmit(
    tcb *ptcb,
    seqnum seq,
    seglen len,
    Bool  *pout_order)
{
    seqspace *sspace = ptcb->ss;
    seqnum seq_last = seq + len - 1;
    quadrant *pquad;
    int rexlen = 0;

    /* unless told otherwise, it's IN order */
    *pout_order = FALSE;

    /* see which quadrant it starts in */
    pquad = whichquad(sspace,seq);

    /* add the new segment into the segment database */
    if (BOUNDARY(seq,seq_last)) {
	/* lives in two different quadrants (can't be > 2) */
	seqnum seq1,seq2;
	u_long len1,len2;

	/* in first quadrant */
	seq1 = seq;
	len1 = LAST_SEQ(QUADNUM(seq1)) - seq1 + 1;
	rexlen = addseg(ptcb,pquad,seq1,len1,pout_order);

	/* in second quadrant */
	seq2 = FIRST_SEQ(QUADNUM(seq_last));
	len2 = len - len1;
	rexlen += addseg(ptcb,pquad->next,seq2,len2,pout_order);
    } else {
	rexlen = addseg(ptcb,pquad,seq,len,pout_order);
    }

    return(rexlen);
}


/********************************************************************/
static int
addseg(
    tcb *ptcb,
    quadrant *pquad,
    seqnum thisseg_firstbyte,
    seglen len,
    Bool  *pout_order)
{
    seqnum thisseg_lastbyte = thisseg_firstbyte + len - 1;
    segment *pseg;
    segment *pseg_new;
    int rexlen = 0;
    Bool split = FALSE;

    /* check each segment in the segment list */
    pseg = pquad->seglist_head;

    /* (optimize expected case, it just goes at the end) */
    if (pquad->seglist_tail && 
	(thisseg_firstbyte > pquad->seglist_tail->seq_lastbyte))
	pseg = NULL;
    for (; pseg != NULL; pseg = pseg->next) {
	if (thisseg_firstbyte > pseg->seq_lastbyte) {
	    /* goes beyond this one */
	    continue;
	}

	if (thisseg_firstbyte < pseg->seq_firstbyte) {
	    /* starts BEFORE this recorded segment */

	    /* if it also FINISHES before this segment, then it's */
	    /* out of order (otherwise it's a resend the collapsed */
	    /* multiple segments into one */
	    if (thisseg_lastbyte < pseg->seq_lastbyte)
		*pout_order = TRUE;

	    /* make a new segment record for it */
	    pseg_new = create_seg(thisseg_firstbyte, len);
	    insert_seg_between(pquad,pseg_new,pseg->prev,pseg);

	    /* see if we overlap the next segment in the list */
	    if (thisseg_lastbyte < pseg->seq_firstbyte) {
		/* we don't overlap, so we're done */
		return(rexlen);
	    } else {
		/* overlap him, split myself in 2 */

		/* adjust new piece to mate with old piece */
		pseg_new->seq_lastbyte = pseg->seq_firstbyte - 1;

		/* pretend to be just the second half of this segment */
		pseg_new->seq_lastbyte = pseg->seq_firstbyte - 1;
		thisseg_firstbyte = pseg->seq_firstbyte;
		len = thisseg_lastbyte - thisseg_firstbyte + 1;

		/* fall through */
	    }
	}

	/* no ELSE, we might have fallen through */
	if (thisseg_firstbyte >= pseg->seq_firstbyte) {
	    /* starts within this recorded sequence */
	    ++pseg->retrans;
	    if (!split)
		rtt_retrans(ptcb,pseg);  /* must be a retransmission */

	    if (thisseg_lastbyte <= pseg->seq_lastbyte) {
		/* entirely contained within this sequence */
		rexlen += len;
		return(rexlen);
	    }
	    /* else */
	    /* we extend beyond this sequence, split ourself in 2 */
	    /* (pretend to be just the second half of this segment) */
	    split = TRUE;
	    rexlen += pseg->seq_lastbyte - thisseg_firstbyte + 1;
	    thisseg_firstbyte = pseg->seq_lastbyte + 1;
	    len = thisseg_lastbyte - thisseg_firstbyte + 1;
	}
    }


    /* if we got to the end, then it doesn't go BEFORE anybody, */
    /* tack it onto the end */
    pseg_new = create_seg(thisseg_firstbyte, len);
    insert_seg_between(pquad,pseg_new,pquad->seglist_tail,NULL);

    return(rexlen);
}



/**********************************************************************/
static segment *
create_seg(
    seqnum seq,
    seglen len)
{
    segment *pseg;

    pseg = (segment *)MallocZ(sizeof(segment));

    pseg->time = current_time;
    pseg->seq_firstbyte = seq;
    pseg->seq_lastbyte = seq + len - 1;

    return(pseg);
}

/**********************************************************************/
static quadrant *
create_quadrant(void)
{
    quadrant *pquad;

    pquad = (quadrant *)MallocZ(sizeof(quadrant));

    return(pquad);
}

/********************************************************************/

static quadrant *
whichquad(
    seqspace *sspace,
    seqnum seq)
{
    quadnum qid = QUADNUM(seq);
    quadrant 	*pquad;
    int		qix;
    int		qix_next;
    int		qix_opposite;
    int		qix_prev;

    /* optimize expected case, it's all set up correctly already */
    qix = qid - 1;
    if ((pquad = sspace->pquad[qix]) && pquad->next && pquad->prev)
	return(pquad);

    /* determine indices of "neighbor" quadrants */
    qix_next     = (qix+1)%4;
    qix_opposite = (qix+2)%4;
    qix_prev     = (qix+3)%4;

    /* make sure that THIS quadrant exists */
    if (sspace->pquad[qix] == NULL) {	
	sspace->pquad[qix] = create_quadrant();
    }

    /* make sure that the quadrant AFTER this one exists */
    if (sspace->pquad[qix_next] == NULL) {
	sspace->pquad[qix_next] = create_quadrant();
    }

    /* make sure that the quadrant BEFORE this one exists */
    if (sspace->pquad[qix_prev] == NULL) {
	sspace->pquad[qix_prev] = create_quadrant();
    }

    /* clear out the opposite side, we don't need it anymore */
    if (sspace->pquad[qix_opposite] != NULL) {
	freequad(&sspace->pquad[qix_opposite]);

	sspace->pquad[qix_opposite] = NULL;
    }

    /* set all the pointers */
    sspace->pquad[qix]->prev = sspace->pquad[qix_prev];
    sspace->pquad[qix]->next = sspace->pquad[qix_next];
    sspace->pquad[qix_next]->prev = sspace->pquad[qix];
    sspace->pquad[qix_prev]->next = sspace->pquad[qix];
    sspace->pquad[qix_next]->next = NULL;
    sspace->pquad[qix_prev]->prev = NULL;

    return(sspace->pquad[qix]);
}



/*********************************************************************/
static void
collapse_quad(
    quadrant *pquad)
{
    Bool freed;
    segment *pseg;
    segment *tmpseg;

    if ((pquad == NULL) || (pquad->seglist_head == NULL))
	return;

    pseg = pquad->seglist_head;
    while (pseg != NULL) {
	freed = FALSE;
	if (pseg->next == NULL)
	    break;

	/* if this segment has not been ACKed, then neither have the */
	/* ones that follow, so no need to continue */
	if (!pseg->acked)
	    break;

	/* if this segment and the next one have both been ACKed and they */
	/* "fit together", then collapse them into one (larger) segment   */
	if (pseg->acked && pseg->next->acked &&
	    (pseg->seq_lastbyte+1 == pseg->next->seq_firstbyte)) {
	    pseg->seq_lastbyte = pseg->next->seq_lastbyte;

	    /* the new ACK count is the ACK count of the later segment */
	    pseg->acked = pseg->next->acked;

	    /* the new "transmit time" is the greater of the two */
	    if (tv_gt(pseg->next->time,pseg->time))
		pseg->time = pseg->next->time;

	    tmpseg = pseg->next;
	    pseg->next = pseg->next->next;
	    if (pseg->next != NULL)
		pseg->next->prev = pseg;
	    if (tmpseg == pquad->seglist_tail)
		pquad->seglist_tail = pseg;
	    free(tmpseg);
	    freed = TRUE;
	}

	if (!freed)
	    pseg = pseg->next;
	/* else, see if the next one also can be collapsed into me */
    }

    /* see if the quadrant is now "full" */
    if ((pquad->seglist_head->seq_lastbyte -
	 pquad->seglist_head->seq_firstbyte + 1) == QUADSIZE) {
	pquad->full = TRUE;
    }
}


static void
insert_seg_between(
    quadrant *pquad,
    segment *pseg_new,
    segment *pseg_before,
    segment *pseg_after)
{
    /* fix forward pointers */
    pseg_new->next = pseg_after;
    if (pseg_after != NULL) {
	pseg_after->prev = pseg_new;
    } else {
	/* I'm the tail of the list */
	pquad->seglist_tail = pseg_new;
    }

    /* fix backward pointers */
    pseg_new->prev = pseg_before;
    if (pseg_before != NULL) {
	pseg_before->next = pseg_new;
    } else {
	/* I'm the head of the list */
	pquad->seglist_head = pseg_new;
    }
}


static enum t_ack
rtt_ackin(
    tcb *ptcb,
    segment *pseg,
    Bool rexmit_prev)
{
    double etime_rtt;
    enum t_ack ret;

	u_long current_size=0;

    /* how long did it take */
    etime_rtt = elapsed(pseg->time,current_time);

    if (rexmit_prev) {
	/* first, check for the situation in which the segment being ACKed */
	/* was sent a while ago, and we've been piddling around */
	/* retransmitting lost segments that came before it */
	ptcb->rtt_last = 0.0;	/* don't use this sample, it's very long */
	etime_rtt = 0.0;

	++ptcb->rtt_nosample;  /* no sample, even though not ambig */
	ret = NOSAMP;
    } else if (pseg->retrans == 0) {
	ptcb->rtt_last = etime_rtt;

	if ((ptcb->rtt_min == 0) || (ptcb->rtt_min > etime_rtt))
	    ptcb->rtt_min = etime_rtt;

	if (ptcb->rtt_max < etime_rtt)
	    ptcb->rtt_max = etime_rtt;

	ptcb->rtt_sum += etime_rtt;
	ptcb->rtt_sum2 += etime_rtt * etime_rtt;
	++ptcb->rtt_count;

	/* Collecting stats for full size segments */
	/* Calculate the current_size of the segment,
	   taking care of possible sequence space wrap around */

	if ( pseg->seq_lastbyte > pseg->seq_firstbyte )
	  current_size = pseg->seq_lastbyte - pseg->seq_firstbyte + 1;
	else
	   /* MAX_32 is 0x1,0000,0000
	   So we don't need the "+ 1" while calculating the size here */
	  current_size = (MAX_32 - pseg->seq_firstbyte)+pseg->seq_lastbyte;

	if ( !ptcb->rtt_full_size || (ptcb->rtt_full_size < current_size) )
	{
		/* Found a bigger segment.. Reset all stats. */
		ptcb->rtt_full_size=current_size;

		ptcb->rtt_full_min=etime_rtt;
		ptcb->rtt_full_max=etime_rtt;
		ptcb->rtt_full_sum=etime_rtt;
		ptcb->rtt_full_sum2=(etime_rtt * etime_rtt);
		ptcb->rtt_full_count=1;
	}
	else if (ptcb->rtt_full_size == current_size)
	{
		++ptcb->rtt_full_count;

		if ((ptcb->rtt_full_min==0) || (ptcb->rtt_full_min>etime_rtt) )
			ptcb->rtt_full_min = etime_rtt;

		if (ptcb->rtt_full_max < etime_rtt)
			ptcb->rtt_full_max = etime_rtt;

		ptcb->rtt_full_sum += etime_rtt;
		ptcb->rtt_full_sum2 += (etime_rtt * etime_rtt);
	}
	ret = NORMAL;
    } else {
	/* retrans, can't use it */
	if ((ptcb->rtt_min_last == 0) || (ptcb->rtt_min_last > etime_rtt))
	    ptcb->rtt_min_last = etime_rtt;

	if (ptcb->rtt_max_last < etime_rtt)
	    ptcb->rtt_max_last = etime_rtt;

	ptcb->rtt_sum_last += etime_rtt;
	ptcb->rtt_sum2_last += etime_rtt * etime_rtt;
	++ptcb->rtt_count_last;

	++ptcb->rtt_amback;  /* ambiguous ACK */

	/* numbers not useful for plotting/dumping */
	ptcb->rtt_last = 0.0;
	etime_rtt = 0.0;

	ret = AMBIG;
    }

    /* dump RTT samples, if asked */
    if (dump_rtt && (etime_rtt != 0.0)) {
	dump_rtt_sample(ptcb,pseg,etime_rtt);
    }

    /* plot RTT samples, if asked */
    if (graph_rtt && (pseg->retrans == 0)) {
	graph_rtt_sample(ptcb,pseg,etime_rtt);
    }

    return(ret);
}



static void
rtt_retrans(
    tcb *ptcb,
    segment *pseg)
{
    double etime;

    if (!pseg->acked) {
	/* if it was acked, then it's been collapsed and these */
	/* are no longer meaningful */
	etime = elapsed(pseg->time,current_time);
	if (pseg->retrans > ptcb->retr_max)
	    ptcb->retr_max = pseg->retrans;

	if (etime > ptcb->retr_max_tm)
	    ptcb->retr_max_tm = etime;
	if ((ptcb->retr_min_tm == 0) || (etime < ptcb->retr_min_tm))
	    ptcb->retr_min_tm = etime;

	ptcb->retr_tm_sum += etime;
	ptcb->retr_tm_sum2 += etime*etime;
	++ptcb->retr_tm_count;
    }

    pseg->time = current_time;
}


enum t_ack
ack_in(
    tcb *ptcb,
    seqnum ack,
    unsigned tcp_data_length)
{
    quadrant *pquad;
    quadrant *pquad_prev;
    segment *pseg;
    Bool changed_one = FALSE;
    Bool intervening_xmits = FALSE;
    timeval last_xmit = {0,0};
    enum t_ack ret = 0;

    /* check each segment in the segment list for the PREVIOUS quadrant */
    pquad = whichquad(ptcb->ss,ack);
    pquad_prev = pquad->prev;
    for (pseg = pquad_prev->seglist_head; pseg != NULL; pseg = pseg->next) {
	if (!pseg->acked) {
	    ++pseg->acked;
	    changed_one = TRUE;
	    ++ptcb->rtt_cumack;

	    /* keep track of the newest transmission */
	    if (tv_gt(pseg->time,last_xmit))
		last_xmit = pseg->time;
	}
    }
    if (changed_one)
	collapse_quad(pquad_prev);

    /* check each segment in the segment list for the CURRENT quadrant */
    changed_one = FALSE;
    for (pseg = pquad->seglist_head; pseg != NULL; pseg = pseg->next) {
	if (ack <= pseg->seq_firstbyte) {
	    /* doesn't cover anything else on the list */
	    break;
	}

	/* keep track of the newest transmission */
	if (tv_gt(pseg->time,last_xmit))
	    last_xmit = pseg->time;

	/* (ELSE) ACK covers this sequence */
	if (pseg->acked) {
	    /* already acked this one */
	    ++pseg->acked;
	    if (ack == (pseg->seq_lastbyte+1)) {
		++ptcb->rtt_dupack; /* one more duplicate ack */
		ret = CUMUL;
		if (pseg->acked == 4) {
		    /* some people say these CAN'T have data */
		    if ((tcp_data_length == 0) ||
			triple_dupack_allows_data) {
			++ptcb->rtt_triple_dupack;
			ret = TRIPLE;
		    }
		}
	    }
	    continue;
	}
	/* ELSE !acked */

	++pseg->acked;
	changed_one = TRUE;

	if (ack == (pseg->seq_lastbyte+1)) {
	    /* if ANY preceding segment was xmitted after this one,
	       the the RTT sample is invalid */
	    intervening_xmits = (tv_gt(last_xmit,pseg->time));

	    ret = rtt_ackin(ptcb,pseg,intervening_xmits);
	} else {
	    /* cumulatively ACKed */
	    ++ptcb->rtt_cumack;
	    ret = CUMUL;
	}
    }
    if (changed_one)
	collapse_quad(pquad);
    return(ret);
}


void
freequad(
    quadrant **ppquad)
{
    segment *pseg;
    segment *pseg_next;

    pseg = (*ppquad)->seglist_head;
    while (pseg && pseg->next) {
	pseg_next = pseg->next;
	free(pseg);
	pseg = pseg_next;
    }
    if (pseg)
	free(pseg);
    free(*ppquad);
    *ppquad = NULL;
}


/* dump RTT samples in milliseconds */
static void
dump_rtt_sample(
    tcb *ptcb,
    segment *pseg,
    double etime_rtt)
{
    /* if the FILE is "-1", couldn't open file */
    if (ptcb->rtt_dump_file == (MFILE *) -1) {
	return;
    }

    /* if the FILE is NULL, open file */
    if (ptcb->rtt_dump_file == (MFILE *) NULL) {
	MFILE *f;
	static char filename[15];

	snprintf(filename,sizeof(filename),"%s2%s%s",
		ptcb->host_letter, ptcb->ptwin->host_letter,
		RTT_DUMP_FILE_EXTENSION);

	if ((f = Mfopen(filename,"w")) == NULL) {
	    perror(filename);
	    ptcb->rtt_dump_file = (MFILE *) -1;
	}

	if (debug)
	    fprintf(stderr,"RTT Sample file is '%s'\n", filename);

	ptcb->rtt_dump_file = f;
    }

    Mfprintf(ptcb->rtt_dump_file,"%lu %lu\n",
	    pseg->seq_firstbyte,
	    (int)(etime_rtt/1000)  /* convert from us to ms */ );
}



/* graph RTT samples in milliseconds */
static void
graph_rtt_sample(
    tcb *ptcb,
    segment *pseg,
    unsigned long etime_rtt)
{
    char title[210];

    /* if the FILE is NULL, open file */
    if (ptcb->rtt_plotter == NO_PLOTTER) {
	char *name_from, *name_to;
	if (ptcb==&ptcb->ptp->a2b) {
	    name_from = ptcb->ptp->a_endpoint;
	    name_to   = ptcb->ptp->b_endpoint;
	} else {
	    name_from = ptcb->ptp->b_endpoint;
	    name_to   = ptcb->ptp->a_endpoint;
	}
	snprintf(title,sizeof(title),"%s_==>_%s (rtt samples)", name_from, name_to);
	ptcb->rtt_plotter = new_plotter(ptcb,NULL,title,
					"time","rtt (ms)",
					RTT_GRAPH_FILE_EXTENSION);
	plotter_perm_color(ptcb->rtt_plotter,"red");

	if (graph_time_zero) {
	    /* set graph zero points */
	    plotter_nothing(ptcb->rtt_plotter, current_time);
	}
	ptcb->rtt_line =
	    new_line(ptcb->rtt_plotter, "rtt", "red");
    }

    if (etime_rtt <= 1)
	return;

    extend_line(ptcb->rtt_line,
		current_time, (int) (etime_rtt / 1000));
}
