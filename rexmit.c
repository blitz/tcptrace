/* 
 * rexmit.c -- Determine if a segment is a retransmit
 * 
 * Author:	Sita Menon
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

/*
This function rexmit() checks to see if a particular packet
is a retransmit. It returns 0 if it is'nt a retransmit and 
returns the number of bytes retransmitted if it is a retransmit - 
considering the fact that it might be a partial retransmit. 
It can also keep track of packets that come out of order.
*/


#include "tcptrace.h"

/* locally global variables*/


/* local routine definitions*/
static int notoverlap(seqspace *,quadrant *,u_long,u_long,u_int *);
static int overlap(seqspace *,quadrant *,u_long,u_long,u_int *);
static seg_acked *create_seg(u_long,u_long);
static quadrant *create_quadrant();
static quadrant *whichquad(seqspace *,u_long);
static quadrant *return_quad(seqspace *,quadrant *,int);
static void collapse_quad(quadrant *);


/* useful macros */

/* boundary: does the segment cross a quadrant boundary? */
#define BOUNDARY(beg,fin) (QUADNUM((beg)) != QUADNUM((fin)))




/*
 * rexmit: is the specified segment a retransmit?
 *   returns: number of retransmitted bytes in segment, 0 if not a rexmit
 *            *pooo to to TRUE if segment is out of order
 */
int rexmit(
    seqspace *sspace,
    u_long seqno,
    u_long len,
    u_int  *pooo) /* out of order */
{
    quadrant *wquad;
    int retval;

    /* unless told otherwise, it's IN order */
    *pooo = 0;

    if ((sspace->begin == 0)&&(sspace->end==0)) {
	sspace->begin = seqno;
	sspace->end = seqno + len-1;
    }

    /* see which quadrant it starts in */
    wquad = whichquad(sspace,seqno);

    /* if first segment in quadrant, there's nothing else to do */
    if (wquad->f_ack == NULL) {
	/* Hmmm... what if the first segments wraps into the next quadrant? */
	wquad->f_ack = create_seg(seqno,len-1);
	wquad->l_ack = wquad->f_ack;
	return(0);
    }

    /* add the new segment into the segment database */
    if (BOUNDARY(seqno,seqno+len-1)) {
	retval = overlap(sspace,wquad,seqno,len-1,pooo);
	collapse_quad(wquad);
	collapse_quad(wquad->next);
    } else {
	retval = notoverlap(sspace,wquad,seqno,len-1,pooo);
	collapse_quad(wquad);
    }

    return(retval);
}


/********************************************************************/
int
notoverlap(
    seqspace *sspace,
    quadrant *wquad,
    u_long seqno,
    u_long len,
    u_int  *pooo) /* out of order */
{
    seg_acked *q,*tmp;
    int last_sent =0,rexlen=0;

    *pooo = 0;
    q = wquad->f_ack;
    while (q != NULL) {
	if ((q->beg<= seqno)&&(seqno<= q->sent_end)) {
	    if (seqno+len<=q->sent_end)
		return(len+1);

	    tmp = q->next;
	    while (tmp!=NULL) {
		if ((seqno+len>=tmp->beg)&&(seqno+len<=tmp->sent_end))
		    return(len+1);
		else if (seqno+len < tmp->beg) {
		    last_sent = tmp->prev->sent_end;
		    break;
		}
		tmp = tmp->next;
	    }
	    if (last_sent == 0 ) {
		rexlen = (wquad->l_ack->sent_end)-seqno+1;
		wquad->l_ack->sent_end = seqno+len;
		sspace->end = seqno+len;
		return(rexlen);
	    } else {
		rexlen = last_sent+1-seqno; 
		tmp->prev->sent_end = seqno+len;
		return(rexlen);
	    }
	} else if ((q->beg<=seqno)&&(seqno>q->sent_end)&&
		   (seqno==(q->sent_end+1))&&(q->next==NULL)) {
	    q->sent_end = q->sent_end +1+ len;	
	    sspace->end = q->sent_end;
	    return(0);
	} else if ((q->next==NULL)&&((seqno>q->sent_end+1)||
				     ((seqno<q->beg)&&(seqno+len<q->beg)))) {
	    if (seqno<q->beg) 
		*pooo = 1;
	    tmp = (seg_acked *)create_seg(seqno,len);
	    if (*pooo) {
		tmp->prev = q->prev;
		if (q->prev)
		    q->prev->next = tmp;
		else
		    wquad->f_ack = tmp;  /* new head of list */
		q->prev = tmp;
		tmp->next = q;
	    } else {
		q->next = tmp;
		tmp->prev = q;
		sspace->end = tmp->sent_end;
	 	wquad->l_ack = tmp;
	    }
	    return(0);
	} else
	    q = q->next;
    }
    /* should never happen */
    return(0);
}

/*******************************************************************/
int overlap(
    seqspace *sspace,
    quadrant *qu,
    u_long seq,
    u_long len,
    u_int  *pooo) /* out of order */
{
    seg_acked *q,*r,*tmp,*temp;
    int partial=0,rexlen=0;

    *pooo = 0;
    q=qu->f_ack;
    while (q!=NULL) {
	if ((seq >= q->beg)&&(seq<=q->sent_end)) {
	    r= qu->next->f_ack;
	    while (r!=NULL) {
		if ((seq+len>=r->beg)&&(seq+len<=r->sent_end))
		    return(len+1);
		else
		    r=r->next;
	    }
	    partial = 1;
	}
	if (!partial)
	    q = q->next;
    }

    if (partial) {
	rexlen= q->sent_end - seq+1;
	tmp = q->next;
	while (tmp!=NULL) {
	    rexlen = rexlen + tmp->sent_end +1 - tmp->beg;
	    tmp = tmp->next;
	}
	qu->l_ack->beg = q->beg;
	qu->l_ack->sent_end = qu->quad_end;
	q->prev->next = qu->l_ack;
	qu->l_ack->prev = q->prev;
	while (q!=qu->l_ack) {
	    temp = q->next;
	    free(q);
	    q=temp;
	}
    } else {
	qu->l_ack->next = create_seg(seq,qu->quad_end-seq);
	qu->l_ack->next->prev = qu->l_ack;
	qu->l_ack = qu->l_ack->next;
	qu->l_ack->next = NULL;
    }


    if ((qu->next->f_ack == NULL)&&(partial)) {
	qu->next->f_ack = create_seg(qu->quad_end+1,(seq+len)-(qu->quad_end+1));
	qu->next->l_ack = qu->next->f_ack;
	qu->next->full = 0;
	sspace->end = seq+len;
	return(rexlen);
    } else if ((qu->next->f_ack!=NULL)&&(seq+len<qu->next->f_ack->beg)
	       &&(!partial)) {
	*pooo = 1;
	tmp = create_seg(qu->quad_end+1,(seq+len)-(qu->quad_end+1));
	tmp->next = qu->next->f_ack;
	qu->next->f_ack->prev = tmp;
	qu->next->f_ack = tmp;
	return(0);
    }

    /* should never happen */
    return(0);
}


/**********************************************************************/
seg_acked *
create_seg(
    u_long seq,
    u_long len)
{
    seg_acked *ptr;

    ptr = (seg_acked *)MallocZ(sizeof(seg_acked));

    ptr->beg = seq;
    ptr->sent_end = seq+len;
    ptr->prev = NULL;
    ptr->next = NULL;

    return(ptr);
}

/**********************************************************************/
quadrant *
create_quadrant()
{
    quadrant *ptr;

    ptr = (quadrant *)MallocZ(sizeof(quadrant));

    return(ptr);
}

/********************************************************************/

quadrant *
whichquad(
    seqspace *sspace,
    u_long seq)
{
    if (IN_Q1(seq)) 
	return(return_quad(sspace,sspace->q1,1));
    else if (IN_Q2(seq))
	return(return_quad(sspace,sspace->q2,2));
    else if (IN_Q3(seq))
	return(return_quad(sspace,sspace->q3,3));
    else if (IN_Q4(seq)) 
	return(return_quad(sspace,sspace->q4,4));
    else {
	fprintf(stderr,"WHICHQUAD internal error\n");
	exit(1);
	return(0);  /* LINT */
    }
}

/*********************************************************************/
quadrant *
return_quad(
    seqspace *sspace,
    quadrant *ptr,
    int id)
{
    if (ptr == NULL) {	
	ptr = create_quadrant();
	ptr->full = 0;
    }

    if (id==1) {
	sspace->q1 = ptr;
	if ((sspace->q2 == NULL)||(sspace->q4==NULL)) {
	    if (sspace->q2 == NULL)
		sspace->q2=create_quadrant();
	    if (sspace->q4 == NULL)
		sspace->q4=create_quadrant();
	    ptr->next = sspace->q2;
	    sspace->q2->prev = sspace->q1;
	    sspace->q2->next = NULL;
	    ptr->prev = sspace->q4;
	    sspace->q4->next = sspace->q1;
	    sspace->q4->prev = NULL;
	    ptr->quad_end = QUADSIZE;
	    if (sspace->q3 != NULL) {
		free((quadrant *)sspace->q3);
		sspace->q3 = NULL;
	    }
	}
    } else if (id==2) {
	sspace->q2 = ptr;
	if  ((sspace->q3==NULL)||(sspace->q1==NULL)) {
	    if (sspace->q3 == NULL)
		sspace->q3=create_quadrant();
	    if (sspace->q1 == NULL)
		sspace->q1=create_quadrant();
	    ptr->next = sspace->q3;
	    sspace->q3->prev = sspace->q2;
	    sspace->q3->next = NULL;
	    ptr->prev = sspace->q1;
	    sspace->q1->next = sspace->q2;
	    sspace->q1->prev = NULL;
	    if (sspace->q4 != NULL) {
		free((quadrant *)sspace->q4);
		sspace->q4 = NULL;
	    }
	}
    } else if (id==3) {
	sspace->q3 = ptr;
	if  ((sspace->q4==NULL)||(sspace->q2==NULL))
	{
	    if (sspace->q4 == NULL)
		sspace->q4=create_quadrant();
	    if (sspace->q2 == NULL)
		sspace->q2=create_quadrant();
	    ptr->next = sspace->q4;
	    sspace->q4->prev = sspace->q3;
	    sspace->q4->next = NULL;
	    ptr->prev = sspace->q2;
	    sspace->q2->next = sspace->q3;
	    sspace->q2->prev = NULL;
	    if (sspace->q1 != NULL) {
		free((quadrant *)sspace->q1);
		sspace->q1 = NULL;
	    }
	}
    } else if (id==4) {
	sspace->q4 = ptr;
	if  ((sspace->q1==NULL)||(sspace->q3==NULL)) {
	    if (sspace->q1 == NULL)
		sspace->q1=create_quadrant();
	    if (sspace->q3 == NULL)
		sspace->q3=create_quadrant();
	    ptr->next = sspace->q1;
	    sspace->q1->prev = sspace->q4;
	    sspace->q1->next = NULL;
	    ptr->prev = sspace->q3;
	    sspace->q3->next = sspace->q4;
	    sspace->q3->prev = NULL;
	    if (sspace->q2 != NULL) {
		free((quadrant *)sspace->q2);
		sspace->q2 = NULL;
	    }
	}
    }
    return(ptr);
}

/*********************************************************************/


#ifdef OLD
void collapse(
    seqspace *sspace)
{
    collapse_quad(sspace->q1);
    collapse_quad(sspace->q2);
    collapse_quad(sspace->q3);
    collapse_quad(sspace->q4);
}
#endif OLD



/*********************************************************************/
void collapse_quad(
    quadrant *pquad)
{
    int freed;
    seg_acked *seg;
    seg_acked *tmp;

    if ((pquad == NULL) || (pquad->f_ack == NULL))
	return;

    seg = pquad->f_ack;
    while (seg != NULL) {
	freed = 0;
	if ((seg->next!=NULL)&&(seg->sent_end+1 == seg->next->beg)) {
	    seg->sent_end = seg->next->sent_end;
	    tmp = seg->next;
	    seg->next = seg->next->next;
	    if (seg->next!= NULL)
		seg->next->prev = seg;
	    if (tmp == pquad->l_ack)
		pquad->l_ack = seg;
	    free(tmp);
	    freed = 1;
	}
	if (!freed)
	    seg = seg->next;
    }

    /* see if the quadrant is now "full" */
    if ((pquad->f_ack->sent_end - pquad->f_ack->beg + 1) == QUADSIZE) {
	pquad->full = 1;
    }
}
