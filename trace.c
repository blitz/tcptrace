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

/* locally global variables */
static int tcp_packet_count = 0;
static int search_count = 0;
static int active_conn_count = 0;
static int closed_conn_count = 0;
static Bool *ignore_pairs = NULL;/* which ones will we ignore */
static Bool bottom_letters = 0;	/* I don't use this anymore */
static Bool more_conns_ignored = FALSE;
static double sample_elapsed_time=0; /* to keep track of owin samples */
static double total_elapsed_time=0; /* to keep track of owin samples */ 
static int num_removed_tcp_pairs = 0;

/* provided globals  */
int num_tcp_pairs = -1;	/* how many pairs we've allocated */
tcp_pair **ttp = NULL;	/* array of pointers to allocated pairs */
int max_tcp_pairs = 64; /* initial value, automatically increases */
u_long tcp_trace_count = 0;


/* local routine definitions */
static tcp_pair *NewTTP(struct ip *, struct tcphdr *);
static tcp_pair *FindTTP(struct ip *, struct tcphdr *, int *, ptp_ptr **);
static void MoreTcpPairs(int num_needed);
static void ExtractContents(u_long seq, u_long tcp_data_bytes,
			    u_long saved_data_bytes, void *pdata, tcb *ptcb);
static Bool check_hw_dups(u_short id, seqnum seq, tcb *ptcb);
static u_long SeqRep(tcb *ptcb, u_long seq);
static void UpdateConnLists(ptp_ptr *tcp_ptr, struct tcphdr *ptcp);
static void UpdateConnList(ptp_ptr *tcp_ptr, 
			   const Bool valid, 
			   ptp_ptr **conn_list_head, 
			   ptp_ptr **conn_list_tail);
static void RemoveOldConns(ptp_ptr **conn_list_head, 
			   ptp_ptr **conn_list_tail,
			   const unsigned expire_interval,
			   const Bool num_conn_check,
			   int *conn_count);
static void RemoveConn(const ptp_ptr *tcp_ptr);
static void RemoveTcpPair(const ptp_ptr *tcp_ptr);



/* options */
Bool show_zero_window = TRUE;
Bool show_rexmit = TRUE;
Bool show_out_order = TRUE;
Bool show_sacks = TRUE;
Bool show_rtt_dongles = FALSE;
Bool show_triple_dupack = TRUE;
Bool show_zwnd_probes = TRUE;
Bool nonames = FALSE;
Bool use_short_names = FALSE;
Bool show_urg = TRUE;
int thru_interval = 10;	/* in segments */


/* what colors to use */
/* choose from: "green" "red" "blue" "yellow" "purple" "orange"
   "magenta" "pink" */
char *window_color	= "yellow";
char *ack_color		= "green";
char *sack_color	= "purple";
char *data_color	= "white";
char *retrans_color	= "red";
char *hw_dup_color	= "blue";
char *out_order_color	= "pink";
char *text_color	= "magenta";
char *default_color	= "white";
char *synfin_color	= "orange";
char *push_color	= "white";	/* top arrow for PUSHed segments */
char *ecn_color		= "yellow";
char *urg_color		= "red";
char *probe_color       = "orange";

/* ack diamond dongle colors */
char *ackdongle_nosample_color	= "blue";
char *ackdongle_ambig_color	= "red";


/* return elapsed time in microseconds */
/* (time2 - time1) */
double
elapsed(
    struct timeval time1,
    struct timeval time2)
{
    struct timeval etime;

    /*sanity check, some of the files have packets out of order */
    if (tv_lt(time2,time1)) {
	return(0.0);
    }

    if (0) {
	fprintf(stderr,"elapsed(%s,", ts2ascii(&time1));
	fprintf(stderr,"%s) is ", ts2ascii(&time2));
    }

    etime = time2;
    tv_sub(&etime, time1);

    if (0)
	fprintf(stderr,"\n\t%s \n", ts2ascii(&etime));

    return((double)etime.tv_sec * 1000000 + (double)etime.tv_usec);
}



/* subtract the rhs from the lhs, result in lhs */
void
tv_sub(struct timeval *plhs, struct timeval rhs)
{
    /* sanity check, lhs MUST BE more than rhs */
    if (tv_lt(*plhs,rhs)) {
	fprintf(stderr,"tvsub(%s,", ts2ascii(plhs));
	fprintf(stderr,"%s) bad timestamp order!\n", ts2ascii(&rhs));
/* 	exit(-1); */
	plhs->tv_sec = plhs->tv_usec = 0;
	return;
    }
    
    if (plhs->tv_usec >= rhs.tv_usec) {
	plhs->tv_usec -= rhs.tv_usec;
    } else if (plhs->tv_usec < rhs.tv_usec) {
	plhs->tv_usec += US_PER_SEC - rhs.tv_usec;
	plhs->tv_sec -= 1;
    }
    plhs->tv_sec -= rhs.tv_sec;
}


/* add the RHS to the LHS, answer in *plhs */
void
tv_add(struct timeval *plhs, struct timeval rhs)
{
    plhs->tv_sec += rhs.tv_sec;
    plhs->tv_usec += rhs.tv_usec;

    if (plhs->tv_usec >= US_PER_SEC) {
	plhs->tv_usec -= US_PER_SEC;
	plhs->tv_sec += 1;
    }
}


/* are the 2 times the same? */
Bool
tv_same(struct timeval lhs, struct timeval rhs)
{
    return((lhs.tv_sec  == rhs.tv_sec) &&
	   (lhs.tv_usec == rhs.tv_usec));
}


/*  1: lhs >  rhs */
/*  0: lhs == rhs */
/* -1: lhs <  rhs */
int
tv_cmp(struct timeval lhs, struct timeval rhs)
{
    if (lhs.tv_sec > rhs.tv_sec) {
	return(1);
    }

    if (lhs.tv_sec < rhs.tv_sec) {
	return(-1);
    }

    /* ... else, seconds are the same */
    if (lhs.tv_usec > rhs.tv_usec)
	return(1);
    else if (lhs.tv_usec == rhs.tv_usec)
	return(0);
    else
	return(-1);
}



/* copy the IP addresses and port numbers into an addrblock structure	*/
/* in addition to copying the address, we also create a HASH value	*/
/* which is based on BOTH IP addresses and port numbers.  It allows	*/
/* faster comparisons most of the time					*/
void
CopyAddr(
    tcp_pair_addrblock *ptpa,
    struct ip *pip,
    portnum	port1,
    portnum	port2)
{
    ptpa->a_port = port1;
    ptpa->b_port = port2;

    if (PIP_ISV4(pip)) { /* V4 */
	IP_COPYADDR(&ptpa->a_address, *IPV4ADDR2ADDR(&pip->ip_src));
	IP_COPYADDR(&ptpa->b_address, *IPV4ADDR2ADDR(&pip->ip_dst));
	/* fill in the hashed address */
	ptpa->hash = ptpa->a_address.un.ip4.s_addr
	    + ptpa->b_address.un.ip4.s_addr
	    + ptpa->a_port + ptpa->b_port;
    } else { /* V6 */
	int i;
	struct ipv6 *pip6 = (struct ipv6 *)pip;
	IP_COPYADDR(&ptpa->a_address, *IPV6ADDR2ADDR(&pip6->ip6_saddr));
	IP_COPYADDR(&ptpa->b_address, *IPV6ADDR2ADDR(&pip6->ip6_daddr));
	/* fill in the hashed address */
	ptpa->hash = ptpa->a_port + ptpa->b_port;
	for (i=0; i < 16; ++i) {
	    ptpa->hash += ptpa->a_address.un.ip6.s6_addr[i];
	    ptpa->hash += ptpa->b_address.un.ip6.s6_addr[i];
	}
    }

    if (debug > 3)
	printf("Hash of (%s:%d,%s:%d) is %d\n",
	       HostName(ptpa->a_address),
	       ptpa->a_port,
	       HostName(ptpa->b_address),
	       ptpa->b_port,
	       ptpa->hash);
}



int
WhichDir(
    tcp_pair_addrblock *ptpa1,
    tcp_pair_addrblock *ptpa2)
{

#ifdef BROKEN_COMPILER
    /* sorry for the ugly nested 'if', but a 4-way conjunction broke my	*/
    /* Optimizer (under 'gcc version cygnus-2.0.2')			*/

    /* same as first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->a_address))
	if (IP_SAMEADDR(ptpa1->b_address, ptpa2->b_address))
	    if ((ptpa1->a_port == ptpa2->a_port))
		if ((ptpa1->b_port == ptpa2->b_port))
		    return(A2B);

    /* reverse of first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->b_address))
	if (IP_SAMEADDR(ptpa1->b_address, ptpa2->a_address))
	    if ((ptpa1->a_port == ptpa2->b_port))
		if ((ptpa1->b_port == ptpa2->a_port))
		    return(B2A);
#else /* BROKEN_COMPILER */
    /* same as first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->a_address) &&
	IP_SAMEADDR(ptpa1->b_address, ptpa2->b_address) &&
	(ptpa1->a_port == ptpa2->a_port) &&
	(ptpa1->b_port == ptpa2->b_port))
	return(A2B);

    /* reverse of first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->b_address) &&
	IP_SAMEADDR(ptpa1->b_address, ptpa2->a_address) &&
	(ptpa1->a_port == ptpa2->b_port) &&
	(ptpa1->b_port == ptpa2->a_port))
	return(B2A);
#endif /* BROKEN_COMPILER */

    /* different connection */
    return(0);
}



int
SameConn(
    tcp_pair_addrblock *ptpa1,
    tcp_pair_addrblock *ptpa2,
    int      *pdir)
{
    /* if the hash values are different, they can't be the same */
    if (ptpa1->hash != ptpa2->hash)
	return(0);

    /* OK, they hash the same, are they REALLY the same function */
    *pdir = WhichDir(ptpa1,ptpa2);
    return(*pdir != 0);
}


static tcp_pair *
NewTTP(
    struct ip *pip,
    struct tcphdr *ptcp)
{
    char title[210];
    tcp_pair *ptp;

    if (0) {
      printf("trace.c:NewTTP() calling MakeTcpPair()\n");
    }
    ptp = MakeTcpPair();
    ++num_tcp_pairs;

    if (!run_continuously) {
      /* make a new one, if possible */
      if ((num_tcp_pairs+1) >= max_tcp_pairs) {
	MoreTcpPairs(num_tcp_pairs+1);
      }
      /* create a new TCP pair record and remember where you put it */
      ttp[num_tcp_pairs] = ptp;
      ptp->ignore_pair = ignore_pairs[num_tcp_pairs];
    }


    /* grab the address from this packet */
    CopyAddr(&ptp->addr_pair,
	     pip, ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    ptp->a2b.time.tv_sec = -1;
    ptp->b2a.time.tv_sec = -1;

    ptp->a2b.host_letter = strdup(NextHostLetter());
    ptp->b2a.host_letter = strdup(NextHostLetter());

    ptp->a2b.ptp = ptp;
    ptp->b2a.ptp = ptp;
    ptp->a2b.ptwin = &ptp->b2a;
    ptp->b2a.ptwin = &ptp->a2b;

    /* fill in connection name fields */
    ptp->a_hostname = strdup(HostName(ptp->addr_pair.a_address));
    ptp->a_portname = strdup(ServiceName(ptp->addr_pair.a_port));
    ptp->a_endpoint =
	strdup(EndpointName(ptp->addr_pair.a_address,
			    ptp->addr_pair.a_port));
    ptp->b_hostname = strdup(HostName(ptp->addr_pair.b_address));
    ptp->b_portname = strdup(ServiceName(ptp->addr_pair.b_port));
    ptp->b_endpoint = 
	strdup(EndpointName(ptp->addr_pair.b_address,
			    ptp->addr_pair.b_port));

    /* init time sequence graphs */
    ptp->a2b.tsg_plotter = ptp->b2a.tsg_plotter = NO_PLOTTER;
    if (graph_tsg && !ptp->ignore_pair) {
	if (!ignore_non_comp || (SYN_SET(ptcp))) {
	    snprintf(title,sizeof(title),"%s_==>_%s (time sequence graph)",
		    ptp->a_endpoint, ptp->b_endpoint);
	    ptp->a2b.tsg_plotter =
		new_plotter(&ptp->a2b,NULL,title,
			    graph_time_zero?"relative time":"time",
			    graph_seq_zero?"sequence offset":"sequence number",
			    PLOT_FILE_EXTENSION);
	    snprintf(title,sizeof(title),"%s_==>_%s (time sequence graph)",
		    ptp->b_endpoint, ptp->a_endpoint);
	    ptp->b2a.tsg_plotter =
		new_plotter(&ptp->b2a,NULL,title,
			    graph_time_zero?"relative time":"time",
			    graph_seq_zero?"sequence offset":"sequence number",
			    PLOT_FILE_EXTENSION);
	    if (graph_time_zero) {
		/* set graph zero points */
		plotter_nothing(ptp->a2b.tsg_plotter, current_time);
		plotter_nothing(ptp->b2a.tsg_plotter, current_time);
	    }
	}
    }

    /* init owin graphs */
    ptp->a2b.owin_plotter = ptp->b2a.owin_plotter = NO_PLOTTER;
    if (graph_owin && !ptp->ignore_pair) {
	if (!ignore_non_comp || (SYN_SET(ptcp))) {
	    snprintf(title,sizeof(title),"%s_==>_%s (outstanding data)",
		    ptp->a_endpoint, ptp->b_endpoint);
	    ptp->a2b.owin_plotter =
		new_plotter(&ptp->a2b,NULL,title,
			    graph_time_zero?"relative time":"time",
			    "Outstanding Data (bytes)",
			    OWIN_FILE_EXTENSION);
	    snprintf(title,sizeof(title),"%s_==>_%s (outstanding data)",
		    ptp->b_endpoint, ptp->a_endpoint);
	    ptp->b2a.owin_plotter =
		new_plotter(&ptp->b2a,NULL,title,
			    graph_time_zero?"relative time":"time",
			    "Outstanding Data (bytes)",
			    OWIN_FILE_EXTENSION);
	    if (graph_time_zero) {
		/* set graph zero points */
		plotter_nothing(ptp->a2b.owin_plotter, current_time);
		plotter_nothing(ptp->b2a.owin_plotter, current_time);
	    }
	    ptp->a2b.owin_line =
		new_line(ptp->a2b.owin_plotter, "owin", "red");
	    ptp->b2a.owin_line =
		new_line(ptp->b2a.owin_plotter, "owin", "red");
	    ptp->a2b.owin_avg_line =
		new_line(ptp->a2b.owin_plotter, "avg owin", "blue");
	    ptp->b2a.owin_avg_line =
		new_line(ptp->b2a.owin_plotter, "avg owin", "blue");
	    ptp->a2b.owin_wavg_line =
		new_line(ptp->a2b.owin_plotter, "wavg owin", "green");
	    ptp->b2a.owin_wavg_line =
		new_line(ptp->b2a.owin_plotter, "wavg owin", "green");
	}
    }

    /* init segment size graphs */
    ptp->a2b.segsize_plotter = ptp->b2a.segsize_plotter = NO_PLOTTER;
    if (graph_segsize && !ptp->ignore_pair) {
	snprintf(title,sizeof(title),"%s_==>_%s (segment size graph)",
		ptp->a_endpoint, ptp->b_endpoint);
	ptp->a2b.segsize_plotter =
	    new_plotter(&ptp->a2b,NULL,title,
			graph_time_zero?"relative time":"time",
			"segment size (bytes)",
			SEGSIZE_FILE_EXTENSION);
	snprintf(title,sizeof(title),"%s_==>_%s (segment size graph)",
		ptp->b_endpoint, ptp->a_endpoint);
	ptp->b2a.segsize_plotter =
	    new_plotter(&ptp->b2a,NULL,title,
			graph_time_zero?"relative time":"time",
			"segment size (bytes)",
			SEGSIZE_FILE_EXTENSION);
	if (graph_time_zero) {
	    /* set graph zero points */
	    plotter_nothing(ptp->a2b.segsize_plotter, current_time);
	    plotter_nothing(ptp->b2a.segsize_plotter, current_time);
	}
	ptp->a2b.segsize_line =
	    new_line(ptp->a2b.segsize_plotter, "segsize", "red");
	ptp->b2a.segsize_line =
	    new_line(ptp->b2a.segsize_plotter, "segsize", "red");
	ptp->a2b.segsize_avg_line =
	    new_line(ptp->a2b.segsize_plotter, "avg segsize", "blue");
	ptp->b2a.segsize_avg_line =
	    new_line(ptp->b2a.segsize_plotter, "avg segsize", "blue");
    }

    /* init RTT graphs */
    ptp->a2b.rtt_plotter = ptp->b2a.rtt_plotter = NO_PLOTTER;

    ptp->a2b.ss = MakeSeqspace();
    ptp->b2a.ss = MakeSeqspace();

    ptp->filename = cur_filename;

    return(ptp);
}



/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
#ifdef SMALL_TABLE
#define HASH_TABLE_SIZE 1021  /* oughta be prime */
#else /* SMALL_TABLE */
#define HASH_TABLE_SIZE 4099  /* oughta be prime */
#endif /* SMALL_TABLE */
static ptp_snap *ptp_hashtable[HASH_TABLE_SIZE] = {NULL};

/* double linked-lists of live and closed connections */
static ptp_ptr	*live_conn_list_head = NULL;
static ptp_ptr	*live_conn_list_tail = NULL;
static ptp_ptr	*closed_conn_list_head = NULL;
static ptp_ptr	*closed_conn_list_tail = NULL;
static timeval	last_update_time = {0, 0};

static tcp_pair *
FindTTP(
    struct ip *pip,
    struct tcphdr *ptcp,
    int *pdir,
    ptp_ptr **tcp_ptr)
{
    ptp_snap **pptph_head = NULL;
    ptp_snap *ptph;
    ptp_snap *ptph_last;
    tcp_pair_addrblock	tp_in;
    int dir;
    hash hval;
    *tcp_ptr = NULL;

    if (debug > 10) {
      printf("trace.c: FindTTP() called\n");
    }

    /* grab the address from this packet */
    CopyAddr(&tp_in, pip, ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    /* grab the hash value (already computed by CopyAddr) */
    hval = tp_in.hash % HASH_TABLE_SIZE;
    

    ptph_last = NULL;
    pptph_head = &ptp_hashtable[hval];
    for (ptph = *pptph_head; ptph; ptph=ptph->next) {
	++search_count;

	if (SameConn(&tp_in,&ptph->addr_pair,&dir)) {
	    /* OK, this looks good, suck it into memory */
	    tcb *thisdir;
	    tcb *otherdir;
	    tcp_pair *ptp;
	    if (run_continuously) {
	      ptp_ptr *ptr = (ptp_ptr *)ptph->ptp;
	      ptp = ptr->ptp;
	    }
	    else {
	      ptp = (tcp_pair *)ptph->ptp;
	    }

	    /* figure out which direction this packet is going */
	    if (dir == A2B) {
		thisdir  = &ptp->a2b;
		otherdir = &ptp->b2a;
	    } else {
		thisdir  = &ptp->b2a;
		otherdir = &ptp->a2b;
	    }

	    /* check for "inactive" */
	    /* (this shouldn't happen anymore, they aren't on the list */
	    if (ptp->inactive) {
 	       if (!run_continuously)
		 continue;
               else {
		 *tcp_ptr = (ptp_ptr *)ptph->ptp;
                 return ((*tcp_ptr)->ptp);
	       }
	    }

	    /* Fri Oct 16, 1998 */
	    /* note: original heuristic was not sufficient.  Bugs */
	    /* were pointed out by Brian Utterback and later by */
	    /* myself and Mark Allman */

	   if (!run_continuously) { 
	    /* check for NEW connection on these same endpoints */
	    /* 1) At least 4 minutes idle time */
	    /*  OR */
	    /* 2) heuristic (we might miss some) either: */
	    /*    this packet has a SYN */
	    /*    last conn saw both FINs and/or RSTs */
	    /*    SYN sequence number outside last window (rfc 1122) */
	    /*      (or less than initial Sequence, */
	    /*       for wrap around trouble)  - Tue Nov  3, 1998*/
	    /*  OR */
	    /* 3) this is a SYN, last had a SYN, seq numbers differ */
	    /* if so, mark it INACTIVE and skip from now on */
	    if (0 && SYN_SET(ptcp)) {
		/* better keep this debugging around, it keeps breaking */
		printf("elapsed: %f sec\n",
		       elapsed(ptp->last_time,current_time)/1000000);
		printf("SYN_SET: %d\n", SYN_SET(ptcp));
		printf("a2b.fin_count: %d\n", ptp->a2b.fin_count);
		printf("b2a.fin_count: %d\n", ptp->b2a.fin_count);
		printf("a2b.reset_count: %d\n", ptp->a2b.reset_count);
		printf("b2a.reset_count: %d\n", ptp->b2a.reset_count);
		printf("dir: %d (%s)\n", dir, dir==A2B?"A2B":"B2A");
		printf("seq:    %lu \n", (u_long)ntohl(ptcp->th_seq));
		printf("winend: %lu \n", otherdir->windowend);
		printf("syn:    %lu \n", otherdir->syn);
		printf("SEQ_GREATERTHAN winend: %d\n", 
		       SEQ_GREATERTHAN(ntohl(ptcp->th_seq),otherdir->windowend));
		printf("SEQ_LESSTHAN init syn: %d\n", 
		       SEQ_LESSTHAN(ntohl(ptcp->th_seq),thisdir->syn));
	    } 

	    if (/* rule 1 */
		(elapsed(ptp->last_time,current_time)/1000000 > (4*60))
		|| /* rule 2 */
		((SYN_SET(ptcp)) && 
		 (((thisdir->fin_count >= 1) ||
		   (otherdir->fin_count >= 1)) ||
		  ((thisdir->reset_count >= 1) ||
		   (otherdir->reset_count >= 1))) &&
		 (SEQ_GREATERTHAN(ntohl(ptcp->th_seq),otherdir->windowend) ||
		  SEQ_LESSTHAN(ntohl(ptcp->th_seq),thisdir->syn)))
		|| /* rule 3 */
		(SYN_SET(ptcp) &&
		 (thisdir->syn_count > 1) &&
		 (thisdir->syn != ntohl(ptcp->th_seq)))) {
		
		if (debug>1) {
		    printf("%s: Marking %p %s<->%s INACTIVE (idle: %f sec)\n",
			   ts2ascii(&current_time),
			   ptp,
			   ptp->a_endpoint, ptp->b_endpoint,
			   elapsed(ptp->last_time,
				   current_time)/1000000);
		    if (debug > 3)
			PrintTrace(ptp);
		}

		/* we won't need this one anymore, remove it from the */
		/* hash table so we won't have to skip over it */
		ptp->inactive = TRUE;
		if (ptph == *pptph_head) {
		    /* head of the list */
		    *pptph_head = ptph->next;
		} else {
		    /* inside the list */
		    ptph_last->next = ptph->next;
		}
		continue;
	    }
	   }

	    /* move to head of access list (unless already there) */
	    if (ptph != *pptph_head) {
		ptph_last->next = ptph->next; /* unlink */
		ptph->next = *pptph_head;     /* move to head */
		*pptph_head = ptph;
	    }

	    if (run_continuously) 
	      (*tcp_ptr) = (ptp_ptr *)ptph->ptp;

	    *pdir = dir;
	    return (ptp);
	}
	ptph_last = ptph;
    }

    /* Didn't find it, make a new one, if possible */
    if (0) {
      printf("trace.c:FindTTP() calling MakePtpSnap()\n");
    }
    ptph = MakePtpSnap();
    if (run_continuously) {
      ptp_ptr *ptr = (ptp_ptr *)MakePtpPtr();
      ptr->prev = NULL;

      if (live_conn_list_head == NULL) {
	ptr->next = NULL;
	live_conn_list_head = ptr;
	live_conn_list_tail = ptr;
      }
      else {
	ptr->next = live_conn_list_head;
	live_conn_list_head->prev = ptr;
	live_conn_list_head = ptr;
      }
      ptr->from = ptph;
      ptr->ptp = NewTTP(pip, ptcp);
      ptph->addr_pair = ptr->ptp->addr_pair;
      ptph->ptp = (void *)ptr;
      if (conn_num_threshold) {
	active_conn_count++;
	if (active_conn_count > max_conn_num) {
	  ptp_ptr *last_ptr = live_conn_list_tail;
	  live_conn_list_tail = last_ptr->prev;
	  live_conn_list_tail->next = NULL;
          RemoveConn(last_ptr);
	  num_removed_tcp_pairs++;
	  active_conn_count--;
	  FreePtpPtr(last_ptr);
	}
      }
    }
    else {
      tcp_pair *tmp = NewTTP(pip,ptcp);
      ptph->addr_pair = tmp->addr_pair;
      ptph->ptp = tmp;
    }
    
    /* put at the head of the access list */
    ptph->next = *pptph_head;
    *pptph_head = ptph;

    *pdir = A2B;
    if (run_continuously) {
      *tcp_ptr = (ptp_ptr *)ptph->ptp;
      return ((*tcp_ptr)->ptp);
    }
    else
      return (tcp_pair *)(ptph->ptp);
}
     
 
static void 
UpdateConnLists(
		ptp_ptr *tcp_ptr,
		struct tcphdr *ptcp)
{
  time_t real_time;
  static int minutes = 0;

  if (0) {
    printf("trace.c: UpdateConnLists() called\n");
  }

  if ((FinCount(tcp_ptr->ptp) > 0) || (ConnReset(tcp_ptr->ptp))) { 
    /* we have FIN or RST */
    if (!tcp_ptr->ptp->inactive) {
       /* this is the only FIN or new RST - remove from list of active conns */
      if (debug > 6) {
	printf("UpdateConnLists: removing conn from list of active conns\n");
      }
      UpdateConnList(tcp_ptr, FALSE, 
		     &live_conn_list_head, 
		     &live_conn_list_tail);
      tcp_ptr->ptp->inactive = TRUE;

      if (conn_num_threshold) {
	active_conn_count--;
	closed_conn_count++;
	if (closed_conn_count > max_conn_num) {
	  ptp_ptr *last_ptr = closed_conn_list_tail;
	  closed_conn_list_tail = last_ptr->prev;
	  closed_conn_list_tail->next = NULL;
	  RemoveConn(last_ptr);
	  num_removed_tcp_pairs++;
	  closed_conn_count--;
	  FreePtpPtr(last_ptr);
	}
      }

      /* put entry into the list of inactive connections */
      if (closed_conn_list_head) {
	tcp_ptr->next = closed_conn_list_head;
	tcp_ptr->prev = NULL;
	closed_conn_list_head->prev = tcp_ptr;
	closed_conn_list_head = tcp_ptr;
      }
      else {
	tcp_ptr->next = NULL;
	tcp_ptr->prev = NULL;
	closed_conn_list_head = tcp_ptr;
	closed_conn_list_tail = tcp_ptr;
      }
    }
    else {
    /* update the list of closed connecitons */
    UpdateConnList(tcp_ptr, TRUE, &closed_conn_list_head, 
		   &closed_conn_list_tail);
    }
  }
  else {/* don't have FIN(s)/RST */
    /* update only list of active connections */
     if (tcp_ptr->ptp->inactive == TRUE) {
	printf("WARNING!!! con is inactive, ptr=%p, con=%p, fin=%i, rst=%i\n", tcp_ptr,
	       tcp_ptr->ptp, FinCount(tcp_ptr->ptp), ConnReset(tcp_ptr->ptp));
	printf("a2b.reset_count=%i, b2a.reset_count=%i, RESET_SET(tcph)=%i\n",
	       tcp_ptr->ptp->a2b.reset_count, tcp_ptr->ptp->b2a.reset_count,
	       RESET_SET(ptcp));
     }
    UpdateConnList(tcp_ptr, TRUE, &live_conn_list_head, &live_conn_list_tail);
  }
  
  /* if we haven't updated the structures for at least update_interval number 
   * of seconds, update list of connections and hash table */
  if ((elapsed(last_update_time, current_time) / 1000000) >= update_interval) {

    real_time = time(&real_time);
    if (debug > 10)
      fprintf(stderr, "%3i program time: %i\tcurrent time: %i\tdifference: %i\n",
              ++minutes, (int)current_time.tv_sec, (int)real_time, 
              (int)(real_time - current_time.tv_sec));
    if (conn_num_threshold) {
      RemoveOldConns(&live_conn_list_head, 
		     &live_conn_list_tail, 
		     remove_live_conn_interval, 
		     TRUE,
		     &active_conn_count);
      RemoveOldConns(&closed_conn_list_head,
		     &closed_conn_list_tail, 
		     remove_closed_conn_interval, 
		     TRUE,
		     &closed_conn_count);
    }
    else {
      RemoveOldConns(&live_conn_list_head, 
		     &live_conn_list_tail, 
		     remove_live_conn_interval, 
		     FALSE,
		     0);
      RemoveOldConns(&closed_conn_list_head,
		     &closed_conn_list_tail, 
		     remove_closed_conn_interval, 
		     FALSE,
		     0);
    }
    last_update_time = current_time;
  }
}



static void
UpdateConnList(
	       ptp_ptr *tcp_ptr,
	       const Bool valid,
	       ptp_ptr **conn_list_head,
	       ptp_ptr **conn_list_tail)
{
  ptp_ptr *ptr_prev;
  ptp_ptr *ptr_next;

  if (0) {
    printf("UpdateConnList() called\n");
  }
  if (tcp_ptr == (*conn_list_head)) {
    if (valid) {
      return;
    }
    else {
      *conn_list_head = tcp_ptr->next;
      if ((*conn_list_tail) == tcp_ptr)
	*conn_list_tail = NULL;
      else
	(*conn_list_head)->prev = NULL;
      return;
    }
  }

  ptr_prev = tcp_ptr->prev;
  ptr_next = tcp_ptr->next;

  ptr_prev->next = ptr_next;

  if (ptr_next)
    ptr_next->prev = ptr_prev;
  if (tcp_ptr == (*conn_list_tail))
    *conn_list_tail = ptr_prev;

  if (valid) {
    tcp_ptr->next = (*conn_list_head);
    tcp_ptr->prev = NULL;
    (*conn_list_head)->prev = tcp_ptr;
    *conn_list_head = tcp_ptr;
  }
  return;
}



static void
RemoveOldConns(
	       ptp_ptr **conn_list_head,
	       ptp_ptr **conn_list_tail,
	       const unsigned expire_interval,
	       const Bool num_conn_check,
	       int *conn_count)
{
  ptp_ptr	*ptr;
  ptp_ptr	*prev_ptr;

  if (0) {
    printf("trace.c: RemoveOldConns() called\n");
  }

  if ((*conn_list_tail) == NULL) {
    return;
  }

  ptr = (*conn_list_tail);
  prev_ptr = ptr->prev;
  for (; prev_ptr != NULL; ptr = prev_ptr, prev_ptr = ptr->prev) {
    if ((elapsed(ptr->ptp->last_time, current_time) / 1000000) >= 
	expire_interval) {
      /* if the connection is old enough, remove the snap from the linked-list
	 and the hash_table */
      ptr->prev->next = NULL;
      *conn_list_tail = ptr->prev;
      RemoveConn(ptr);
      num_removed_tcp_pairs++;
      if (0) {
	printf("trace.c:RemoveOldConns() calling FreePtpSnap()\n");
      }
      FreePtpPtr(ptr);
      if (num_conn_check)
	--(*conn_count);
    }
    else {
      break;
    }
  }

  if (((*conn_list_head)->ptp->last_time.tv_sec != 0) &&
      ((elapsed((*conn_list_head)->ptp->last_time, current_time) / 1000000) >= 
       expire_interval)) {
    *conn_list_head = NULL;
    *conn_list_tail = NULL;
    RemoveConn(ptr);
    num_removed_tcp_pairs++;
    FreePtpPtr(ptr);
    if (num_conn_check)
      --(*conn_count);
  }
}



/* remove tcp pair from the hash table */
static void
RemoveConn(
	   const ptp_ptr *tcp_ptr)
{
  ptp_snap	*ptph;
  ptp_ptr	*ptr;
  hash		hval;

  if (0) {
    printf("trace.c: RemoveConn(%p %s<->%s) called\n", 
            tcp_ptr->ptp, tcp_ptr->ptp->a_endpoint, tcp_ptr->ptp->b_endpoint);
  }

  ModulesPerOldConn(tcp_ptr->ptp);

  hval = tcp_ptr->ptp->addr_pair.hash % HASH_TABLE_SIZE;

  if (ptp_hashtable[hval]) {
    /* if the needed connection is at the beginning of the list, then remove it
       and don't go trough the list */
    ptr = (ptp_ptr *)ptp_hashtable[hval]->ptp;
    if (ptr->ptp == tcp_ptr->ptp) {
      ptph = ptp_hashtable[hval];
      ptp_hashtable[hval] = ptp_hashtable[hval]->next;
      RemoveTcpPair(tcp_ptr);
      if (0) {
	printf("trace.c:RemoveConn() calling FreePtpSnap()\n");
      }
      FreePtpSnap(ptph);

      return;
    }
    /* the first ptp_snap on the list is not what we need  - go through 
       the list */
    for (ptph = ptp_hashtable[hval]; ptph->next; ptph = ptph->next) {
      ptr = (ptp_ptr *)ptph->next->ptp;
      if (ptr->ptp == tcp_ptr->ptp) {
      /* delete ptph->next */
	ptp_snap *temp_ptph = ptph->next;
	ptph->next = temp_ptph->next;
	RemoveTcpPair(tcp_ptr);
	if (0) {
	  printf("trace.c:RemoveConn() calling FreePtpSnap()\n");
	}
	FreePtpSnap(temp_ptph);
	return;
      }  
    }
  }
}



static void
RemoveTcpPair(
	      const ptp_ptr *tcp_ptr)
{
  int	i = 0;
  tcp_pair *ptp = tcp_ptr->ptp;

  if (0) {
    printf("trace.c: RemoveTcpPair(%p) called\n", tcp_ptr->ptp);
  }
  
  free(ptp->a2b.host_letter);
  free(ptp->b2a.host_letter);

  free(ptp->a_hostname);
  free(ptp->a_portname);
  free(ptp->a_endpoint);

  free(ptp->b_hostname);
  free(ptp->b_portname);
  free(ptp->b_endpoint);

  if (ptp->a2b.owin_line) {
    free(ptp->a2b.owin_line);
  }
  if (ptp->a2b.owin_avg_line) {
    free(ptp->a2b.owin_avg_line);
  }
  if (ptp->a2b.owin_wavg_line) {
    free(ptp->a2b.owin_avg_line);
  }
  if (ptp->b2a.owin_line) {
    free(ptp->b2a.owin_line);
  }
  if (ptp->b2a.owin_avg_line) {
    free(ptp->b2a.owin_avg_line);
  }
  if (ptp->b2a.owin_wavg_line) {
    free(ptp->b2a.owin_wavg_line);
  }

  if (ptp->a2b.segsize_line) {
    free(ptp->a2b.segsize_line);
  }
  if (ptp->a2b.segsize_avg_line) {
    free(ptp->a2b.segsize_avg_line);
  }
  if (ptp->b2a.segsize_line) {
    free(ptp->b2a.segsize_line);
  }
  if (ptp->b2a.segsize_avg_line) {
    free(ptp->b2a.segsize_avg_line);
  }

  if (ptp->a2b.ss) {
    for (i = 0; i < 4; i++) {
      if (ptp->a2b.ss->pquad[i] != NULL) {
	freequad(&ptp->a2b.ss->pquad[i]);
      }
    }
    FreeSeqspace(ptp->a2b.ss);
  }

  if (ptp->b2a.ss) {
    for (i = 0; i < 4; i++) {
      if (ptp->b2a.ss->pquad[i] != NULL) {
	freequad(&ptp->b2a.ss->pquad[i]);
      }
    }
    FreeSeqspace(ptp->b2a.ss);
  }

  FreeTcpPair(ptp);
}



tcp_pair *
dotrace(
    struct ip *pip,
    struct tcphdr *ptcp,
    void *plast)
{
    struct tcp_options *ptcpo;
    tcp_pair	*ptp_save;
    int		tcp_length;
    int		tcp_data_length;
    u_long	start;
    u_long	end;
    tcb		*thisdir;
    tcb		*otherdir;
    tcp_pair	tp_in;
    PLOTTER	to_tsgpl;
    PLOTTER	from_tsgpl;
    PLOTTER     tlinepl;
    Bool	retrans;
    Bool 	probe;
	Bool 	probe;
    Bool	ecn_ce = FALSE;
    Bool	ecn_echo = FALSE;
    Bool	cwr = FALSE;
    Bool        urg = FALSE;
    int		retrans_num_bytes;
    Bool	out_order;	/* out of order */
    u_short	th_sport;	/* source port */
    u_short	th_dport;	/* destination port */
    tcp_seq	th_seq;		/* sequence number */
    tcp_seq	th_ack;		/* acknowledgement number */
    u_short	th_win;		/* window */
    u_long	eff_win;	/* window after scaling */
    u_short     th_urp;         /* URGENT pointer */
    short	ip_len;		/* total length */
    enum t_ack	ack_type=NORMAL; /* how should we draw the ACK */
    seqnum	old_this_windowend; /* for graphing */
    ptp_ptr	*tcp_ptr = NULL;

    /* make sure we have enough of the packet */
    if ((char *)ptcp + sizeof(struct tcphdr)-1 > (char *)plast) {
	if (warn_printtrunc)
	    fprintf(stderr,
		    "TCP packet %lu truncated too short to trace, ignored\n",
		    pnum);
	++ctrunc;
	return(NULL);
    }


    /* convert interesting fields to local byte order */
    th_seq   = ntohl(ptcp->th_seq);
    th_ack   = ntohl(ptcp->th_ack);
    th_sport = ntohs(ptcp->th_sport);
    th_dport = ntohs(ptcp->th_dport);
    th_win   = ntohs(ptcp->th_win);
    th_urp   = ntohs(ptcp->th_urp);
    ip_len   = gethdrlength(pip, plast) + getpayloadlength(pip,plast);

    /* make sure this is one of the connections we want */
    ptp_save = FindTTP(pip,ptcp,&dir, &tcp_ptr);

    ++tcp_packet_count;

    if (ptp_save == NULL) {
	return(NULL);
    }

    ++tcp_trace_count;

    if (run_continuously && (tcp_ptr == NULL)) {
      fprintf(stderr, "Did not initialize tcp pair pointer\n");
      exit(1);
    }

    /* do time stats */
    if (ZERO_TIME(&ptp_save->first_time)) {
	ptp_save->first_time = current_time;
    }
    ptp_save->last_time = current_time;


    /* bug fix:  it's legal to have the same end points reused.  The */
    /* program uses a heuristic of looking at the elapsed time from */
    /* the last packet on the previous instance and the number of FINs */
    /* in the last instance.  If we don't increment the fin_count */
    /* before bailing out in "ignore_pair" below, this heuristic breaks */

    /* figure out which direction this packet is going */
    if (dir == A2B) {
	thisdir  = &ptp_save->a2b;
	otherdir = &ptp_save->b2a;
    } else {
	thisdir  = &ptp_save->b2a;
	otherdir = &ptp_save->a2b;
    }

    /* meta connection stats */
    if (SYN_SET(ptcp))
	++thisdir->syn_count;
    if (RESET_SET(ptcp))
	++thisdir->reset_count;
    if (FIN_SET(ptcp))
	++thisdir->fin_count;

    /* end bug fix */


    /* compute the "effective window", which is the advertised window */
    /* with scaling */
    if (ACK_SET(ptcp) || SYN_SET(ptcp)) {
	eff_win = (u_long) th_win;

	/* N.B., the window_scale stored for the connection DURING 3way */
	/* handshaking is the REQUESTED scale.  It's only valid if both */
	/* sides request scaling.  AFTER we've seen both SYNs, that field */
	/* is reset (above) to contain zero.  Note that if we */
	/* DIDN'T see the SYNs, the windows will be off. */
 	/* Jamshid: Remember that the window is never scaled in SYN */
 	/* packets, as per RFC 1323. */
 	if (thisdir->f1323_ws && otherdir->f1323_ws && !SYN_SET(ptcp))
	    eff_win <<= thisdir->window_scale;
    } else {
	eff_win = 0;
    }

    
    /* idle-time stats */
    if (!ZERO_TIME(&thisdir->last_time)) {
	u_llong itime = elapsed(thisdir->last_time,current_time);
	if (itime > thisdir->idle_max)
	    thisdir->idle_max = itime;
    }
    thisdir->last_time = current_time;
    

    /* calculate data length */
    tcp_length = getpayloadlength(pip, plast);
    tcp_data_length = tcp_length - (4 * TH_OFF(ptcp));

    /* calc. data range */
    start = th_seq;
    end = start + tcp_data_length;

    /* seq. space wrap around stats */
    /* If all four quadrants have been visited and the current packet
     * is in the same quadrant as the syn, check if latest seq. num is
     * wrapping past the syn. If it is, increment wrap_count
     */
    if ((thisdir->quad1 && thisdir->quad2 && thisdir->quad3 && thisdir->quad4)) {
	if ((IN_Q1(thisdir->syn) && (IN_Q1(end))) ||  (IN_Q2(thisdir->syn) && (IN_Q2(end))) || ((IN_Q3(thisdir->syn) && (IN_Q3(end))) || ((IN_Q4(thisdir->syn) && (IN_Q4(end)))))) {
	    if (end >= thisdir->syn) {
		if (debug>1)
		    fprintf(stderr, "\nWARNING : sequence space wrapped around here \n");
		thisdir->seq_wrap_count++;
		thisdir->quad1=0;
		thisdir->quad2=0;
		thisdir->quad3=0;
		thisdir->quad4=0;
	    }
	}
    } 

    /* Mark the visited quadrants */
    if (!thisdir->quad1) {
	if (IN_Q1(start) || IN_Q1(end))
	    thisdir->quad1=1;
    } 
    if (!thisdir->quad2) {
	if (IN_Q2(start) || IN_Q2(end))
	    thisdir->quad2=1;
    }
    if (!thisdir->quad3) {
	if (IN_Q3(start) || IN_Q3(end))
	    thisdir->quad3=1;
    }
    if (!thisdir->quad4) {
	if (IN_Q4(start) || IN_Q4(end))
	    thisdir->quad4=1;
    }
    
    /* record sequence limits */
    if (SYN_SET(ptcp)) {
	/* error checking - better not change! */
	if ((thisdir->syn_count > 1) && (thisdir->syn != start)) {
	    /* it changed, that shouldn't happen! */
	    if (warn_printbad_syn_fin_seq)
		fprintf(stderr, "\
%s->%s: rexmitted SYN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
			thisdir->host_letter,thisdir->ptwin->host_letter,
			thisdir->syn, start,
			(int)(elapsed(ptp_save->first_time,current_time)/1000000));
	    thisdir->bad_behavior = TRUE;
	}
	thisdir->syn = start;
	otherdir->ack = start;
		/* bug fix for Rob Austein <sra@epilogue.com> */
    }
    if (FIN_SET(ptcp)) {
	/* bug fix, if there's data here too, we need to bump up the FIN */
	/* (psc data file shows example) */
	u_long fin = start + tcp_data_length;
	/* error checking - better not change! */
	if ((thisdir->fin_count > 1) && (thisdir->fin != fin)) {
	    /* it changed, that shouldn't happen! */
	    if (warn_printbad_syn_fin_seq)
		fprintf(stderr, "\
%s->%s: rexmitted FIN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
			thisdir->host_letter,thisdir->ptwin->host_letter,
			thisdir->fin, fin,
			(int)(elapsed(ptp_save->first_time,current_time)/1000000));
	    thisdir->bad_behavior = TRUE;
	}
	thisdir->fin = fin;
    }

    /* "ONLY" bug fix - Wed Feb 24, 1999 */
    /* the tcp-splicing heuristic needs "windowend", which was only being */
    /* calculated BELOW the "only" point below.  Move that part of the */
    /* calculation up here! */

    /* remember the OLD window end for graphing */
    /* (bug fix - Thu Aug 12, 1999) */
    old_this_windowend = thisdir->windowend;

    if (ACK_SET(ptcp)) {
	thisdir->windowend = th_ack + eff_win;
    }
    /* end bugfix */



    /***********************************************************************/
    /***********************************************************************/
    /* if we're ignoring this connection, do no further processing	   */
    /***********************************************************************/
    /***********************************************************************/
    if (ptp_save->ignore_pair) {
	return(ptp_save);
    }

    /* save to a file if requested */
    if (output_filename) {
	PcapSavePacket(output_filename,pip,plast);
    }

    /* now, print it if requested */
    if (printem && !printallofem) {
	printf("Packet %lu\n", pnum);
	printpacket(0,		/* original length not available */
		    (char *)plast - (char *)pip + 1,
		    NULL,0,	/* physical stuff not known here */
		    pip,plast,thisdir);
		    pip,plast);

    /* grab the address from this packet */
    CopyAddr(&tp_in.addr_pair, pip,
	     th_sport, th_dport);


    /* simple bookkeeping */
    if (PIP_ISV6(pip)) {
	++thisdir->ipv6_segments;
    }


    /* plotter shorthand */
    to_tsgpl     = otherdir->tsg_plotter;
    from_tsgpl   = thisdir->tsg_plotter;
   

    /* check the options */
    ptcpo = ParseOptions(ptcp,plast);
    if (ptcpo->mss != -1)
	thisdir->mss = ptcpo->mss;
    if (ptcpo->ws != -1) {
	thisdir->window_scale = ptcpo->ws;
	thisdir->f1323_ws = TRUE;
    }

    if (ptcpo->tsval != -1) {
	thisdir->f1323_ts = TRUE;
    }
    /* NOW, unless BOTH sides asked for window scaling in their SYN	*/
    /* segments, we aren't using window scaling */
    if (!SYN_SET(ptcp) &&
	((!thisdir->f1323_ws) || (!otherdir->f1323_ws))) {
	thisdir->window_scale = otherdir->window_scale = 0;
    }

    /* check sacks */
    if (ptcpo->sack_req) {
	thisdir->fsack_req = 1;
    }
    if (ptcpo->sack_count > 0) {
	++thisdir->sacks_sent;
    }

    /* unless both sides advertised sack, we shouldn't see them, otherwise
    urg = FALSE;
    if (tcp_data_length > 0) {
	thisdir->data_pkts += 1;
	if (PUSH_SET(ptcp))
	    thisdir->data_pkts_push += 1;
	thisdir->data_bytes += tcp_data_length;
        if (URGENT_SET(ptcp)) {     /* Checking if URGENT bit is set */
	    urg = TRUE; 
	    thisdir->urg_data_pkts += 1;
	    thisdir->urg_data_bytes += th_urp;
	}
       	if (tcp_data_length > thisdir->max_seg_size)
	    thisdir->max_seg_size = tcp_data_length;
	if ((thisdir->min_seg_size == 0) ||
	    (tcp_data_length < thisdir->min_seg_size))
	    thisdir->min_seg_size = tcp_data_length;
	/* record first and last times for data (Mallman) */
	if (ZERO_TIME(&thisdir->first_data_time))
	    thisdir->first_data_time = current_time;
	thisdir->last_data_time = current_time;
    }

    /* total packets stats */
    ++ptp_save->packets;
    ++thisdir->packets;

    /* If we are using window scaling, update the win_scaled_pkts counter */
    if (graph_tput) {
	DoThru(thisdir,tcp_data_length);
    }

    /* segment size graphs */
    if ((tcp_data_length > 0) && (thisdir->segsize_plotter != NO_PLOTTER)) {
	extend_line(thisdir->segsize_line, current_time, tcp_data_length);
	extend_line(thisdir->segsize_avg_line, current_time,
		    thisdir->data_bytes / thisdir->data_pkts);
    }

    /* sequence number stats */
    if ((thisdir->min_seq == 0) && (start != 0)) {
	thisdir->min_seq = start; /* first byte in this segment */
	thisdir->max_seq = end;	  /* last byte in this segment */
    }
    if (SEQ_GREATERTHAN (end,thisdir->max_seq)) {
	thisdir->max_seq = end;
    }
    thisdir->latest_seq = end;


    /* check for hardware duplicates */
    /* only works for IPv4, IPv6 has no mandatory ID field */
    if (PIP_ISV4(pip) && docheck_hw_dups)
	hw_dup = check_hw_dups(pip->ip_id, th_seq, thisdir);


    /* Kevin Lahey's ECN code */
    /* only works for IPv4 */
    if (PIP_ISV4(pip)) {
	ecn_ce = IP_ECT(pip) && IP_CE(pip);
    }
    cwr = CWR_SET(ptcp);
    ecn_echo = ECN_ECHO_SET(ptcp);

    /* save the stream contents, if requested */
    if (tcp_data_length > 0) {
	u_char *pdata = (u_char *)ptcp + TH_OFF(ptcp)*4;
	u_long saved;
	u_long	missing;

	saved = tcp_data_length;
	if ((char *)pdata + tcp_data_length > ((char *)plast+1))
	    saved = (char *)plast - (char *)pdata + 1;

	/* see what's missing */
	missing = tcp_data_length - saved;
	if (missing > 0) {
	    thisdir->trunc_bytes += missing;
	    ++thisdir->trunc_segs;
	}

	if (save_tcp_data)
	    ExtractContents(start,tcp_data_length,saved,pdata,thisdir);
    }

    /* do rexmit stats */
    retrans = FALSE;
    probe = FALSE;
    out_order = FALSE;
    retrans_num_bytes = 0;
    if (SYN_SET(ptcp) || FIN_SET(ptcp) || tcp_data_length > 0) {
	int len = tcp_data_length;
	int retrans_cnt=0;
	
	if (SYN_SET(ptcp)) ++len;
	if (FIN_SET(ptcp)) ++len;

								
	/* Don't consider for rexmit, if the send window is 0 */
	/* We are probably doing window probing.. */
	if(otherdir->win_last==0 && otherdir->packets > 0){ 
		probe=TRUE;
		thisdir->num_zwnd_probes++;	
		thisdir->zwnd_probe_bytes += tcp_data_length;
	}
	else
		retrans_cnt = retrans_num_bytes = rexmit(thisdir,start, len, &out_order);

	if (out_order)
	    ++thisdir->out_order_pkts;

	/* count anything NOT retransmitted as "unique" */
	/* exclude SYN and FIN */
	if (SYN_SET(ptcp)) {
	    /* don't count the SYN as data */
	    --len;
	    /* if the SYN was rexmitted, then don't count it */
	    if (thisdir->syn_count > 1)
		--retrans_cnt;
	}
	if (FIN_SET(ptcp)) {
	    /* don't count the FIN as data */
	    --len;
	    /* if the FIN was rexmitted, then don't count it */
	    if (thisdir->fin_count > 1)
		--retrans_cnt;
	}
	if (!probe){
		if(retrans_cnt < len)
	    	thisdir->unique_bytes += (len - retrans_cnt);
	    }
    }


    /* do rtt stats */
    if (ACK_SET(ptcp)) {
	ack_type = ack_in(otherdir,th_ack,tcp_data_length,eff_win);
	ack_type = ack_in(otherdir,th_ack,tcp_data_length);
	if ( (th_ack == (otherdir->syn+1)) &&
		 (otherdir->syn_count == 1) )
		 otherdir->rtt_3WHS=otherdir->rtt_last; 
		 /* otherdir->rtt_last was set in the call to ack_in() */
		
    }


    /* plot out-of-order segments, if asked */
    if (out_order && (from_tsgpl != NO_PLOTTER) && show_out_order) {
	plotter_perm_color(from_tsgpl, out_order_color);
	plotter_text(from_tsgpl, current_time, SeqRep(thisdir,end),
		     "a", "O");
	if (bottom_letters)
	    plotter_text(from_tsgpl, current_time,
			 SeqRep(thisdir,thisdir->min_seq)-1500,
			 "c", "O");
    }

    /* stats for rexmitted data */
    if (retrans_num_bytes>0) {
	retrans = TRUE;
	thisdir->rexmit_pkts += 1;
	thisdir->LEAST++;
	/* don't color the SYNs and FINs, it's confusing, we'll do them */
	/* differently below... */
	if (!(FIN_SET(ptcp)||SYN_SET(ptcp)) &&
	    from_tsgpl != NO_PLOTTER && show_rexmit) {
	    plotter_perm_color(from_tsgpl, retrans_color);
	    plotter_text(from_tsgpl, current_time, SeqRep(thisdir,end),
			 "a", hw_dup?"HD":"R");
	    if (bottom_letters)
		plotter_text(from_tsgpl, current_time,
			     SeqRep(thisdir,thisdir->min_seq)-1500,
			     "c", hw_dup?"HD":"R");
	}
    } else {
	thisdir->seq = end;
    }
   
    if(probe) {
        if(from_tsgpl != NO_PLOTTER && show_zwnd_probes){
	    plotter_perm_color(from_tsgpl,probe_color);
	    plotter_text(from_tsgpl,current_time,SeqRep (thisdir,end),
			  "b", "P");
	 }
     }

    /* draw the packet */
    if (from_tsgpl != NO_PLOTTER) {
	plotter_perm_color(from_tsgpl, data_color);
	if (SYN_SET(ptcp)) {		/* SYN  */
	    /* if we're using time offsets from zero, it's easier if */
	    /* both graphs (a2b and b2a) start at the same point.  That */
	    /* will only happen if the "left-most" graphic is in the */
	    /* same place in both.  To make sure, mark the SYNs */
	    /* as a green dot in the other direction */
	    if (ACK_SET(ptcp)) {
		plotter_temp_color(from_tsgpl, ack_color);
		plotter_dot(from_tsgpl,
			    ptp_save->first_time, SeqRep(thisdir,start));
	    }
	    plotter_perm_color(from_tsgpl,
			       hw_dup?hw_dup_color:
			       retrans_num_bytes>0?retrans_color:
			       synfin_color);
	    plotter_diamond(from_tsgpl, current_time, SeqRep(thisdir,start));
	    plotter_text(from_tsgpl, current_time,
			 SeqRep(thisdir,start+1), "a",
			 hw_dup?"HD SYN":
			 retrans_num_bytes>0?"R SYN":
			 "SYN");
	    plotter_uarrow(from_tsgpl, current_time, SeqRep(thisdir,start+1));
	    plotter_line(from_tsgpl,
			 current_time, SeqRep(thisdir,start),
			 current_time, SeqRep(thisdir,start+1));
	} else if (FIN_SET(ptcp)) {	/* FIN  */
	   /* Wed Sep 18, 2002 - bugfix
	    /* we'll plot the FIN from 'end' to 'end+1' because the
	       segment might have data in it too (normally not) */
	    plotter_perm_color(from_tsgpl,
			       hw_dup?hw_dup_color:
			       retrans_num_bytes>0?retrans_color:
			       synfin_color);
			 SeqRep(thisdir,end+1), "a",
			 hw_dup?"HD FIN":
			 retrans_num_bytes>0?"R FIN":
			 "FIN");
	   

	    plotter_box(from_tsgpl, current_time, SeqRep(thisdir,end+1));
	    plotter_darrow(from_tsgpl, current_time, SeqRep(thisdir,end));
	    plotter_line(from_tsgpl,
			 current_time, SeqRep(thisdir,end),
			 current_time, SeqRep(thisdir,end+1));
	    if (hw_dup) {
		plotter_perm_color(from_tsgpl, hw_dup_color);
	    } else if (retrans) {
		plotter_perm_color(from_tsgpl, retrans_color);
	    }
	    plotter_darrow(from_tsgpl, current_time, SeqRep(thisdir,start));
	    if (PUSH_SET(ptcp)) {
		/* colored diamond is PUSH */
		plotter_temp_color(from_tsgpl, push_color);
		plotter_diamond(from_tsgpl,
				current_time, SeqRep(thisdir,end));
		plotter_temp_color(from_tsgpl, push_color);
		plotter_dot(from_tsgpl, current_time, SeqRep(thisdir,end));
	    } else {
		plotter_uarrow(from_tsgpl, current_time, SeqRep(thisdir,end));
	    }
	    plotter_line(from_tsgpl,
			 current_time, SeqRep(thisdir,start),
			 current_time, SeqRep(thisdir,end));
	} else if (tcp_data_length == 0) {
	    /* for Brian Utterback */
	    if (graph_zero_len_pkts) {
		/* draw zero-length packets */
		/* shows up as an X, really two arrow heads */
		plotter_darrow(from_tsgpl,
			       current_time, SeqRep(thisdir,start));
		plotter_uarrow(from_tsgpl,
			       current_time, SeqRep(thisdir,start));
	    }
	}

	/* Kevin Lahey's code */
	/* XXX:  can this overwrite other labels!? */
	if (cwr || ecn_ce) {
	    plotter_perm_color(from_tsgpl, ecn_color);
	    plotter_diamond(from_tsgpl,
			    current_time, SeqRep(thisdir,start));
	    plotter_text(from_tsgpl, current_time, SeqRep(thisdir, start), "a",
			 cwr ? (ecn_ce ? "CWR CE" : "CWR") : "CE");
	}
       
    }
   
    /* Plotting URGENT data */
    if(urg) {
        if(from_tsgpl != NO_PLOTTER && show_urg){
	    plotter_perm_color(from_tsgpl,urg_color);
	    plotter_text(from_tsgpl,current_time,SeqRep (thisdir,end),
			   "a", "U");
	 } 
    }
     }
    /* check for RESET */
    if (RESET_SET(ptcp)) {
	u_long plot_at;

	/* if there's an ACK in this packet, plot it there */
	/* otherwise, plot it at the last valid ACK we have */
	if (ACK_SET(ptcp))
	    plot_at = th_ack;
	else
	    plot_at = thisdir->ack;

	if (to_tsgpl != NO_PLOTTER) {
	    plotter_temp_color(to_tsgpl, text_color);
	    plotter_text(to_tsgpl,
			 current_time, SeqRep(otherdir,plot_at),
			 current_time, SeqRep(thisdir,plot_at),
	}
	if (from_tsgpl != NO_PLOTTER) {
	    plotter_temp_color(from_tsgpl, text_color);
	    plotter_text(from_tsgpl,
			 current_time, SeqRep(thisdir,start),
			 "a", "RST_OUT");
	}
	if (ACK_SET(ptcp))
	    ++thisdir->ack_pkts;

        if (run_continuously) {
            UpdateConnLists(tcp_ptr, ptcp); /*Ramani: Call this even in nocontinuous mode */
            UpdateConnLists(tcp_ptr, ptcp);
	return(ptp_save);
    }
   
    /* do window stats (include first SYN too!) */
	thisdir->win_last=eff_win;

    if (ACK_SET(ptcp) || SYN_SET(ptcp)) {
	if (eff_win > thisdir->win_max)
	    thisdir->win_max = eff_win;

	/* If we *are* going to use window scaling,
	/* If we *are* going to use window scaling, ignore the window
	size that appeared in SYN packet as being counted as win_min 
	for this direction. 
	Instead, treat the smallest, window-scaled, window advertisement
	as win_min. 

	We have a flag "window_stats_updated_for_scaling" 
	in either direction of the connection, that gets turned ON, the 
	moment we find that both sides have agreed to use window
	scaling and this is the first packet in either direction
	with scaled window. */
	   
	     ( thisdir->f1323_ws && otherdir->f1323_ws && !SYN_SET(ptcp) &&
		!thisdir->window_stats_updated_for_scaling  
		   (thisdir->window_scale > 0) &&
		   !thisdir->window_stats_updated_for_scaling  
	     ) ) {
			thisdir->window_stats_updated_for_scaling=TRUE;
			thisdir->win_min = eff_win;
	else if ((eff_win > 0) &&
	    ((thisdir->win_min == 0) ||
	     (eff_win < thisdir->win_min)))
	    thisdir->win_min = eff_win;
	
    }

    /* draw the ack and win in the other plotter */
    if (ACK_SET(ptcp)) {
	seqnum ack = th_ack;
	u_long winend;

	winend = ack + eff_win;
      
	if (eff_win == 0) {
	    ++thisdir->win_zero_ct;
	    if (to_tsgpl != NO_PLOTTER && show_zero_window) {
		plotter_temp_color(to_tsgpl, text_color);
		plotter_text(to_tsgpl,
			     current_time, SeqRep(otherdir,winend),
			     "a", "Z");
		if (bottom_letters) {
		    plotter_temp_color(to_tsgpl, text_color);
		    plotter_text(to_tsgpl,
				 current_time,
				 SeqRep(otherdir,otherdir->min_seq)-1500,
				 "a", "Z");
		}
	    }
	}

	++thisdir->ack_pkts;
	if ((tcp_data_length == 0) &&
	    !SYN_SET(ptcp) && !FIN_SET(ptcp) && !RESET_SET(ptcp)) {
	    ++thisdir->pureack_pkts;
	}
	    

	if (to_tsgpl != NO_PLOTTER && thisdir->time.tv_sec != -1) {
	    plotter_perm_color(to_tsgpl, ack_color);
	    plotter_line(to_tsgpl,
			 thisdir->time, SeqRep(otherdir,thisdir->ack),
			 current_time, SeqRep(otherdir,thisdir->ack));
	    if (thisdir->ack != ack) {
		plotter_line(to_tsgpl,
			     current_time, SeqRep(otherdir,thisdir->ack),
			     current_time, SeqRep(otherdir,ack));
		if (show_rtt_dongles) {
		    /* draw dongles for "interesting" acks */
		    switch (ack_type) {
		      case NORMAL:	/* normal case */
			/* no dongle */
			break;
		      case CUMUL:	/* cumulative */
			/* won't happen, not plotted here */
			break;
		      case TRIPLE:	/* triple dupacks */
			/* won't happen, not plotted here */
			break;
		      case AMBIG:	/* ambiguous */
			plotter_temp_color(to_tsgpl, ackdongle_ambig_color);
			plotter_diamond(to_tsgpl, current_time,
					SeqRep(otherdir,ack));
			break;
		      case NOSAMP:	/* acks retransmitted stuff cumulatively */
			plotter_temp_color(to_tsgpl, ackdongle_nosample_color);
			plotter_diamond(to_tsgpl, current_time,
					SeqRep(otherdir,ack));
			break;
		    }
		}
	    } else {
		plotter_dtick(to_tsgpl, current_time, SeqRep(otherdir,ack));
		if (show_triple_dupack && (ack_type == TRIPLE)) {
		    plotter_text(to_tsgpl, current_time,
				 SeqRep(otherdir,ack),
				 "a", "3");  /* '3' is for triple dupack */
		}
	    }

	    /* Kevin Lahey's code */
	    if (ecn_echo && !SYN_SET(ptcp)) {
	        plotter_perm_color(to_tsgpl, ecn_color);
		plotter_diamond(to_tsgpl, current_time, SeqRep(otherdir, ack));
	    }

	    plotter_perm_color(to_tsgpl, window_color);
	    plotter_line(to_tsgpl,
			 thisdir->time, SeqRep(otherdir,old_this_windowend),
			 current_time, SeqRep(otherdir,old_this_windowend));
	    if (old_this_windowend != winend) {
		plotter_line(to_tsgpl,
			     current_time, SeqRep(otherdir,old_this_windowend),
			     current_time, SeqRep(otherdir,winend));
	    } else {
		plotter_utick(to_tsgpl, current_time, SeqRep(otherdir,winend));
	    }
	}

	/* track the most sack blocks in a single ack */
	if (ptcpo->sack_count > 0) {
	    ++thisdir->num_sacks;
	    if (ptcpo->sack_count > thisdir->max_sack_blocks) 
		thisdir->max_sack_blocks = ptcpo->sack_count;


	if (to_tsgpl != NO_PLOTTER && show_sacks
	    && (ptcpo->sack_count > 0)) {
	    int scount;
	    seqnum sack_top = ptcpo->sacks[0].sack_right;

	    plotter_perm_color(to_tsgpl, sack_color);
	    for (scount = 0; scount < ptcpo->sack_count; ++scount) {
		plotter_line(to_tsgpl,
			     current_time,
			     SeqRep(otherdir,ptcpo->sacks[scount].sack_left),
			     current_time,
			     SeqRep(otherdir,ptcpo->sacks[scount].sack_right));
		/* make it easier to read multiple sacks by making them look like
		   |-----|  (sideways)
		*/
		plotter_htick(to_tsgpl,
			      current_time,
			      SeqRep(otherdir,ptcpo->sacks[scount].sack_left));
		plotter_htick(to_tsgpl,
			      current_time,
			      SeqRep(otherdir,ptcpo->sacks[scount].sack_right));

		/* if there's more than one, label the order */
		/* purple number to the right of the top ("right" edge) */
		if (ptcpo->sack_count > 1) {
		    char buf[5]; /* can't be more than 1 digit! */
		    snprintf(buf,sizeof(buf),"%u",scount+1);	/* 1-base, rather than 0-base */
		    plotter_text(to_tsgpl,
				 current_time,
				 SeqRep(otherdir,ptcpo->sacks[scount].sack_right),
				 "r", buf);
		}

		/* maintain the highest SACK so we can label them all at once */
		if (SEQ_GREATERTHAN(ptcpo->sacks[scount].sack_right, sack_top))
		    sack_top = ptcpo->sacks[scount].sack_right;
	    }
	    /* change - just draw the 'S' above the highest one */
	    plotter_text(to_tsgpl, current_time,
			 SeqRep(otherdir,sack_top),
			 "a", "S");  /* 'S' is for Sack */
	}
	thisdir->time = current_time;
	thisdir->ack = ack;

/* 	thisdir->windowend = winend;  (moved above "only" point) */
    }  /* end ACK_SET(ptcp) */

    /* do stats for initial window (first slow start) */
    /* (if there's data in this and we've NEVER seen */
    /*  an ACK coming back from the other side) */
    /* this is for Mark Allman for slow start testing -- Mon Mar 10, 1997 */
    if (!otherdir->data_acked && ACK_SET(ptcp)
	&& ((otherdir->syn+1) != th_ack)) {
	otherdir->data_acked = TRUE;
    }
    if ((tcp_data_length > 0) && (!thisdir->data_acked)) {
	if (!retrans) {
	    /* don't count it if it was retransmitted */
	    thisdir->initialwin_bytes += tcp_data_length;
	    thisdir->initialwin_segs += 1;
	}
    }

    /* do stats for congestion window (estimated) */
    /* estimate the congestion window as the number of outstanding */
    /* un-acked bytes */
    if (!SYN_SET(ptcp) && !out_order && !retrans) {
	u_long owin;
	/* If there has been no ack from the other direction, owin is just 
	 * bytes in this pkt.
	 */
	if (otherdir->ack == 0){
		owin = end - start ;
	}
	else {
		/* ack  always acks 'received + 1' bytes, so subtract 1 
		 * for owin */
		owin = end - (otherdir->ack - 1);
	}
	
	if (owin > thisdir->owin_max)
	    thisdir->owin_max = owin;
	if ((owin > 0) &&
	    ((thisdir->owin_min == 0) ||
	     (owin < thisdir->owin_min)))
	    thisdir->owin_min = owin;
	
	thisdir->owin_tot += owin;	
       	thisdir->owin_count++;

	/* adding mark's suggestion of weighted owin */
	if (thisdir->previous_owin_sample_time.tv_sec == 0) {
	  /* if this is first ever sample for thisdir */
		thisdir->previous_owin_sample_time = thisdir->last_time;
		thisdir->previous_owin_sample = owin;
	}
	else { 
		/* weight each owin sample with the duration that it exists for */
        	sample_elapsed_time = (elapsed(thisdir->previous_owin_sample_time, ptp_save->last_time))/1000000;
        	total_elapsed_time = (elapsed(ptp_save->first_time, ptp_save->last_time))/1000000;
		thisdir->owin_wavg += (u_llong)((thisdir->previous_owin_sample) * sample_elapsed_time);
		/* graph owin_wavg */
		if (thisdir->owin_plotter != NO_PLOTTER) {
			extend_line(thisdir->owin_wavg_line, thisdir->previous_owin_sample_time,
		        	(total_elapsed_time)?((u_llong)((thisdir->owin_wavg)/total_elapsed_time)):0);
		} 
	    	thisdir->previous_owin_sample_time = thisdir->last_time;
		thisdir->previous_owin_sample = owin;
	}

	/* graph owin */
	if (thisdir->owin_plotter != NO_PLOTTER) {
	    extend_line(thisdir->owin_line, current_time, owin);
	    extend_line(thisdir->owin_avg_line, current_time,
			(thisdir->owin_count?(thisdir->owin_tot/thisdir->owin_count):0)); 
	}
    }
    if (run_continuously) {
      UpdateConnLists(tcp_ptr, ptcp);
    }

    return(ptp_save);
}



void
trace_done(void)
{
    tcp_pair *ptp;
    FILE *f_passfilter = NULL;
    int ix;

  if (!run_continuously) {
    if (!printsuppress) {
	if (tcp_trace_count == 0) {
	    fprintf(stdout,"%sno traced TCP packets\n", comment);
	    fprintf(stdout,"no traced TCP packets\n");
	} else {
	    fprintf(stdout,"%sTCP connection info:\n", comment);
	    fprintf(stdout,"TCP connection info:\n");
    }

    if (!printbrief)
	fprintf(stdout,"%s%d TCP %s traced:\n",
	fprintf(stdout,"%d TCP %s traced:\n",
		num_tcp_pairs==0?"connection":"connections");
    if (ctrunc > 0) {
	fprintf(stdout,
		"%s*** %lu packets were too short to process at some point\n",
		"*** %lu packets were too short to process at some point\n",
	if (!warn_printtrunc)
	    fprintf(stdout,"%s\t(use -w option to show details)\n", comment);
	    fprintf(stdout,"\t(use -w option to show details)\n");
    if (debug>1)
	fprintf(stdout,"%saverage TCP search length: %d\n",
	fprintf(stdout,"average TCP search length: %d\n",
		search_count / tcp_packet_count);
    /* complete the "idle time" calculations using NOW */
    for (ix = 0; ix <= num_tcp_pairs; ++ix) {
	tcp_pair *ptp = ttp[ix];
	tcb *thisdir; 
	u_llong itime;

	/* if it's CLOSED, skip it */
	if ((FinCount(ptp)>=2) || (ConnReset(ptp)))
	    continue;

	/* a2b direction */
	thisdir = &ptp->a2b;
	if (!ZERO_TIME(&thisdir->last_time)) {
	    itime = elapsed(thisdir->last_time,current_time);
	    if (itime > thisdir->idle_max)
		thisdir->idle_max = itime;
	}
	    

	/* b2a direction */
	thisdir = &ptp->b2a;
	if (!ZERO_TIME(&thisdir->last_time)) {
	    itime = elapsed(thisdir->last_time,current_time);
	    if (itime > thisdir->idle_max)
		thisdir->idle_max = itime;
	}
    }
  }

    /* if we're filtering, see which connections pass */
    if (filter_output) {
	static int count = 0;

	/* file to dump matching connection numbers into */
	f_passfilter = fopen(PASS_FILTER_FILENAME,"w+");
	if (f_passfilter == NULL) {
	    perror(PASS_FILTER_FILENAME);
	    exit(-1);
	}

      if (!run_continuously) {
	/* mark the connections to ignore */
	for (ix = 0; ix <= num_tcp_pairs; ++ix) {
	    ptp = ttp[ix];
	    if (PassesFilter(ptp)) {
		if (++count == 1)
		    fprintf(f_passfilter,"%d", ix+1);
		else
		    fprintf(f_passfilter,",%d", ix+1);
	    } else {
		/* else ignore it */
		ptp->ignore_pair = TRUE;
	    }
	}
      }
    }


  if (!run_continuously) {
    /* print each connection */
    if (!printsuppress) {
        Bool first = TRUE; /* Used with <SP>-separated-values
	    ptp = ttp[ix];

	    if (!ptp->ignore_pair) {
		if ((printbrief) && (!ignore_non_comp || ConnComplete(ptp))) {
		if (printbrief) {
		    PrintBrief(ptp);
		} else if (!ignore_non_comp || ConnComplete(ptp)) {
		    if(csv || tsv || (sv != NULL)) {
		    if (ix > 0)
			fprintf(stdout,"================================\n");
		    fprintf(stdout,"TCP connection %d:\n", ix+1);
		}
	    }
	}
    }
  }
  
    /* if we're filtering, close the file */
    if (filter_output) {
	fprintf(f_passfilter,"\n");
	fclose(f_passfilter);
    }

    if ((debug>2) && !nonames)
	cadump();
}

static void
MoreTcpPairs(
    int num_needed)
{
    int new_max_tcp_pairs;
    int i;

    if (num_needed < max_tcp_pairs)
	return;

    new_max_tcp_pairs = max_tcp_pairs * 4;
    while (new_max_tcp_pairs < num_needed)
	new_max_tcp_pairs *= 4;
    
    if (debug)
	printf("trace: making more space for %d total TCP pairs\n",
	       new_max_tcp_pairs);

    /* enlarge array to hold any pairs that we might create */
    ttp = ReallocZ(ttp,
		   max_tcp_pairs * sizeof(tcp_pair *),
		   new_max_tcp_pairs * sizeof(tcp_pair *));

    /* enlarge array to keep track of which ones to ignore */
    ignore_pairs = ReallocZ(ignore_pairs,
			    max_tcp_pairs * sizeof(Bool),
			    new_max_tcp_pairs * sizeof(Bool));
    if (more_conns_ignored)
	for (i=max_tcp_pairs; i < new_max_tcp_pairs;++i)
	    ignore_pairs[i] = TRUE;

    max_tcp_pairs = new_max_tcp_pairs;
}


void
trace_init(void)
{
    static Bool initted = FALSE;

    if (0) {
      printf("trace_init called\n");
    }

    if (run_continuously) {
      if (ignore_pairs) {
	free(ignore_pairs);
	ignore_pairs = NULL;
      }
      if (ttp) {
	free(ttp);
	ttp = NULL;
      }
      more_conns_ignored = FALSE;
    }

    if (initted)
	return;

    initted = TRUE;

    /* create an array to hold any pairs that we might create */
    ttp = (tcp_pair **) MallocZ(max_tcp_pairs * sizeof(tcp_pair *));

    /* create an array to keep track of which ones to ignore */
    ignore_pairs = (Bool *) MallocZ(max_tcp_pairs * sizeof(Bool));
    if (!run_continuously) {
        /* create an array to hold any pairs that we might create */
        ttp = (tcp_pair **) MallocZ(max_tcp_pairs * sizeof(tcp_pair *));
      
        /* create an array to keep track of which ones to ignore */
        ignore_pairs = (Bool *) MallocZ(max_tcp_pairs * sizeof(Bool));
    }

    cainit();
    Minit();
}


void
IgnoreConn(
    int ix)
{
    if (debug) fprintf(stderr,"ignoring conn %d\n", ix);

//    trace_init();
    if (run_continuously) {
      fprintf(stderr, "Warning: cannot ignore connections in continuous mode\n");
      return;
    }

    trace_init();
    --ix;

    MoreTcpPairs(ix);

    more_conns_ignored = FALSE;
    ignore_pairs[ix] = TRUE;
}


void
OnlyConn(
    int ix_only)
{
    int ix;
    static Bool cleared = FALSE;
	
    if (debug) fprintf(stderr,"only printing conn %d\n", ix_only);

//    trace_init();
    if (run_continuously) {
      fprintf(stderr, "Warning: cannot ignore connections in continuous mode\n");
      return;
    }

    trace_init();
    --ix_only;

    MoreTcpPairs(ix_only);

    if (!cleared) {
	for (ix = 0; ix < max_tcp_pairs; ++ix) {
	    ignore_pairs[ix] = TRUE;
	}
	cleared = TRUE;
    }

    more_conns_ignored = TRUE;
    ignore_pairs[ix_only] = FALSE;
}


/* get a long (4 byte) option (to avoid address alignment problems) */
static u_long
get_long_opt(
    void *ptr)
{
    u_long l;
    memcpy(&l,ptr,sizeof(u_long));
    return(l);
}


/* get a short (2 byte) option (to avoid address alignment problems) */
static u_short
get_short_opt(
    void *ptr)
{
    u_short s;
    memcpy(&s,ptr,sizeof(u_short));
    return(s);
}


struct tcp_options *
ParseOptions(
    struct tcphdr *ptcp,
    void *plast)
{
    static struct tcp_options tcpo;
    struct sack_block *psack;
    u_char *pdata;
    u_char *popt;
    u_char *plen;

    popt  = (u_char *)ptcp + sizeof(struct tcphdr);
    pdata = (u_char *)ptcp + TH_OFF(ptcp)*4;

    /* init the options structure */
    memset(&tcpo,0,sizeof(tcpo));
    tcpo.mss = tcpo.ws = tcpo.tsval = tcpo.tsecr = -1;
    tcpo.sack_req = 0;
    tcpo.sack_count = -1;
    tcpo.echo_req = tcpo.echo_repl = -1;
    tcpo.cc = tcpo.ccnew = tcpo.ccecho = -1;

    /* a quick sanity check, the unused (MBZ) bits must BZ! */
    if (warn_printbadmbz) {
	if (TH_X2(ptcp) != 0) {
	    fprintf(stderr,
		    "TCP packet %lu: 4 reserved bits are not zero (0x%01x)\n",
		    pnum, TH_X2(ptcp));
	}
	if ((ptcp->th_flags & 0xc0) != 0) {
	    fprintf(stderr,
		    "TCP packet %lu: upper flag bits are not zero (0x%02x)\n",
		    pnum, ptcp->th_flags);
	}
    } else {
	static int warned = 0;
	if (!warned &&
	    ((TH_X2(ptcp) != 0) || ((ptcp->th_flags & 0xc0) != 0))) {
	    warned = 1;
	    fprintf(stderr, "\
TCP packet %lu: reserved bits are not all zero.  \n\
\tFurther warnings disabled, use '-w' for more info\n",
		    pnum);
	}
    }

    /* looks good, now check each option in turn */
    while (popt < pdata) {
	plen = popt+1;

	/* check for truncation error */
	if ((char *)popt > (char *)plast) {
	    if (warn_printtrunc)
		fprintf(stderr,"\
ParseOptions: packet %lu too short to parse remaining options\n", pnum);
	    ++ctrunc;
	    break;
	}

#define CHECK_O_LEN(opt) \
	if (*plen == 0) { \
	    if (warn_printtrunc) fprintf(stderr, "\
ParseOptions: packet %lu %s option has length 0, skipping other options\n", \
                                           pnum,opt); \
	    popt = pdata; break;} \
	if ((char *)popt + *plen - 1 > (char *)(plast)) { \
	    if (warn_printtrunc) \
		fprintf(stderr, "\
ParseOptions: packet %lu %s option truncated, skipping other options\n", \
              pnum,opt); \
	    ++ctrunc; \
	    popt = pdata; break;} \


	switch (*popt) {
	  case TCPOPT_EOL: ++popt; break;
	  case TCPOPT_NOP: ++popt; break;
	  case TCPOPT_MAXSEG:
	    CHECK_O_LEN("TCPOPT_MAXSEG");
	    tcpo.mss = ntohs(get_short_opt(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_WS:
	    CHECK_O_LEN("TCPOPT_WS");
	    tcpo.ws = *((u_char *)(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_TS:
	    CHECK_O_LEN("TCPOPT_TS");
	    tcpo.tsval = ntohl(get_long_opt(popt+2));
	    tcpo.tsecr = ntohl(get_long_opt(popt+6));
	    popt += *plen;
	    break;
	  case TCPOPT_ECHO:
	    CHECK_O_LEN("TCPOPT_ECHO");
	    tcpo.echo_req = ntohl(get_long_opt(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_ECHOREPLY:
	    CHECK_O_LEN("TCPOPT_ECHOREPLY");
	    tcpo.echo_repl = ntohl(get_long_opt(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_CC:
	    CHECK_O_LEN("TCPOPT_CC");
	    tcpo.cc = ntohl(get_long_opt(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_CCNEW:
	    CHECK_O_LEN("TCPOPT_CCNEW");
	    tcpo.ccnew = ntohl(get_long_opt(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_CCECHO:
	    CHECK_O_LEN("TCPOPT_CCECHO");
	    tcpo.ccecho = ntohl(get_long_opt(popt+2));
	    popt += *plen;
	    break;
	  case TCPOPT_SACK_PERM:
	    CHECK_O_LEN("TCPOPT_SACK_PERM");
	    tcpo.sack_req = 1;
	    popt += *plen;
	    break;
	  case TCPOPT_SACK:
	    /* see which bytes are acked */
	    CHECK_O_LEN("TCPOPT_SACK");
	    tcpo.sack_count = 0;
	    psack = (sack_block *)(popt+2);  /* past the kind and length */
	    popt += *plen;
	    while ((char *)psack < (char *)popt) {
		struct sack_block *psack_local =
		    &tcpo.sacks[(unsigned)tcpo.sack_count];
		/* warning, possible alignment problem here, so we'll
		   use memcpy() and hope for the best */
		/* better use -fno-builtin to avoid gcc alignment error
		   in GCC 2.7.2 */
		memcpy(psack_local, psack, sizeof(sack_block));

		/* convert to local byte order (Jamshid Mahdavi) */
		psack_local->sack_left  = ntohl(psack_local->sack_left);
		psack_local->sack_right = ntohl(psack_local->sack_right);

		++psack;
		if ((char *)psack > ((char *)plast+1)) {
		    /* this SACK block isn't all here */
		    if (warn_printtrunc)
			fprintf(stderr,
				"packet %lu: SACK block truncated\n",
				pnum);
		    ++ctrunc;
		    break;
		}
		++tcpo.sack_count;
		if (tcpo.sack_count > MAX_SACKS) {
		    /* this isn't supposed to be able to happen */
		    fprintf(stderr,
			    "Warning, internal error, too many sacks!!\n");
		    tcpo.sack_count = MAX_SACKS;
		}
	    }
	    break;
	  default:
	    if (debug)
		fprintf(stderr,
			"Warning, ignoring unknown TCP option 0x%x\n",
			*popt);
	    CHECK_O_LEN("TCPOPT_UNKNOWN");

	    /* record it anyway... */
	    if (tcpo.unknown_count < MAX_UNKNOWN) {
		int ix = tcpo.unknown_count; /* make lint happy */
		tcpo.unknowns[ix].unkn_opt = *popt;
		tcpo.unknowns[ix].unkn_len = *plen;
	    }
	    ++tcpo.unknown_count;
	    
	    popt += *plen;
	    break;
	}
    }

    return(&tcpo);
}



static void
ExtractContents(
    u_long seq,
    u_long tcp_data_bytes,
    u_long saved_data_bytes,
    void *pdata,
    tcb *ptcb)
{
    u_long missing;
    long offset;
    u_long fptr;
	/* Maximum filename could be :
		aaaaaaaa2bbbbbbbb_contents.dat which
		takes 8+1+8+ size of the extension */
    static char filename[MAX_HOSTLETTER_LEN
					+1      /* for "2" */
					+MAX_HOSTLETTER_LEN
					+sizeof(CONTENTS_FILE_EXTENSION)
					+1];    /* for terminating NULL. */

    if (debug > 2)
	fprintf(stderr,
		"ExtractContents(seq:%ld  bytes:%ld  saved_bytes:%ld) called\n",
		seq, tcp_data_bytes, saved_data_bytes);

    if (saved_data_bytes == 0)
	return;

    /* how many bytes do we have? */
    missing = tcp_data_bytes - saved_data_bytes;
    if ((debug > 2) && (missing > 0)) {
	fprintf(stderr,"ExtractContents: missing %ld bytes (%ld-%ld)\n",
		missing,tcp_data_bytes,saved_data_bytes);
    }

    
    /* if the FILE is "-1", couldn't open file */
    if (ptcb->extr_contents_file == (MFILE *) -1) {
	return;
    }

    /* if the FILE is NULL, open file */
    snprintf(filename,sizeof(filename),"%s2%s%s", ptcb->host_letter, ptcb->ptwin->host_letter,
	    CONTENTS_FILE_EXTENSION);
    if (ptcb->extr_contents_file == (MFILE *) NULL) {
	MFILE *f;

	if ((f = Mfopen(filename,"w")) == NULL) {
	    perror(filename);
	    ptcb->extr_contents_file = (MFILE *) -1;
	}

	if (debug)
	    fprintf(stderr,"TCP contents file is '%s'\n", filename);

	ptcb->extr_contents_file = f;

	if (ptcb->syn_count == 0) {
	    /* we haven't seen the SYN.  This is bad because we can't tell */
	    /* if there is data BEFORE this, which makes it tough to store */
	    /* the file.  Let's be optimistic and hope we don't see */
	    /* anything before this point.  Otherwise, we're stuck */
	    ptcb->extr_lastseq = seq;
	} else {
	    /* beginning of the file is the data just past the SYN */
	    ptcb->extr_lastseq = ptcb->syn+1;
	}
	/* in any case, anything before HERE is illegal (fails for very */
	/* long files - FIXME */
	ptcb->extr_initseq = ptcb->extr_lastseq;
    }

    /* it's illegal for the bytes to be BEFORE extr_initseq unless the file */
    /* is "really long" (seq space has wrapped around) - FIXME(ugly) */
    if ((SEQCMP(seq,ptcb->extr_initseq) < 0) &&
	(ptcb->data_bytes < (0xffffffff/2))) {
	/* if we haven't (didn't) seen the SYN, then can't do this!! */
	if (debug>1) {
	    fprintf(stderr,
		    "ExtractContents: skipping data, preceeds first segment\n");
	    fprintf(stderr,"\t and I didnt' see the SYN\n");
	}
	return;
    }

    /* see where we should start writing */
    /* a little complicated, because we want to support really long files */
    offset = SEQCMP(seq,ptcb->extr_lastseq);
    

    if (debug>10)
	fprintf(stderr,
		"TRYING to save %ld bytes from stream '%s2%s' at offset %ld\n",
		saved_data_bytes,
		ptcb->host_letter, ptcb->ptwin->host_letter,
		offset);

    /* seek to the correct place in the file */
    if (Mfseek(ptcb->extr_contents_file, offset, SEEK_CUR) == -1) {
	perror("fseek");
	exit(-1);
    }

    /* see where we are */
    fptr = Mftell(ptcb->extr_contents_file);

    if (debug>1)
	fprintf(stderr,
		"Saving %ld bytes from '%s2%s' at offset %ld in file '%s'\n",
		saved_data_bytes,
		ptcb->host_letter, ptcb->ptwin->host_letter,
		fptr, filename);

    /* store the bytes */
    if (Mfwrite(pdata,1,saved_data_bytes,ptcb->extr_contents_file)
	!= saved_data_bytes) {
	perror("fwrite");
	exit(-1);
    }

    /* go back to where we started to not confuse the next write */
    ptcb->extr_lastseq = seq;
    if (Mfseek(ptcb->extr_contents_file, fptr, SEEK_SET) == -1) {
	perror("fseek 2");
	exit(-1);
    }
}


/* check for not-uncommon error of hardware-level duplicates
   (same IP ID and TCP sequence number) */
static Bool
check_hw_dups(
    u_short id,
    seqnum seq,
    tcb *tcb)
{
    int i;
    struct str_hardware_dups *pshd;

    /* see if we've seen this one before */
    for (i=0; i < SEGS_TO_REMEMBER; ++i) {
	pshd = &tcb->hardware_dups[i];
	
	if ((pshd->hwdup_seq == seq) && (pshd->hwdup_id == id) &&
	    (pshd->hwdup_seq != 0) && (pshd->hwdup_id != 0)) {
	    /* count it */
	    ++tcb->num_hardware_dups;
	    if (warn_printhwdups) {
		printf("%s->%s: saw hardware duplicate of TCP seq %lu, IP ID %u (packet %lu == %lu)\n",
		       tcb->host_letter,tcb->ptwin->host_letter,
		       seq, id, pnum,pshd->hwdup_packnum);
	    }
	    return(TRUE);
	}
    }

    /* remember it */
    pshd = &tcb->hardware_dups[tcb->hardware_dups_ix];
    pshd->hwdup_seq = seq;
    pshd->hwdup_id = id;
    pshd->hwdup_packnum = pnum;
    tcb->hardware_dups_ix = (tcb->hardware_dups_ix+1) % SEGS_TO_REMEMBER;

    return(FALSE);
}


/* given a tcp_pair and a packet, tell me which tcb it is */
struct tcb *
ptp2ptcb(
    tcp_pair *ptp,
    struct ip *pip,
    struct tcphdr *ptcp)
{
    int dir = 0;
    tcp_pair tp_in;

    /* grab the address from this packet */
    CopyAddr(&tp_in.addr_pair, pip,
	     ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    /* check the direction */
    if (!SameConn(&tp_in.addr_pair,&ptp->addr_pair,&dir))
	return(NULL);  /* not found, internal error */

    if (dir == A2B)
	return(&ptp->a2b);
    else
	return(&ptp->b2a);
}


/* represent the sequence numbers absolute or relative to 0 */
static u_long
SeqRep(
    tcb *ptcb,
    u_long seq)
{
    if (graph_seq_zero) {
	return(seq - ptcb->min_seq);
    } else {
	return(seq);
    }
}


/*------------------------------------------------------------------------
 *  cksum  -  Return 16-bit ones complement of 16-bit ones complement sum 
 *------------------------------------------------------------------------
 */
static u_short
cksum(
    void *pvoid,		/* any alignment is legal */
    int nbytes)
{
    u_char *pchar = pvoid;
    u_long sum = 0;

    while (nbytes >= 2) {
	/* can't assume pointer alignment :-( */
	sum += (pchar[0]<<8);
	sum += pchar[1];

	pchar+=2;
	nbytes -= 2;
    }

    /* special check for odd length */
    if (nbytes == 1) {
	sum += (pchar[0]<<8);
	/* lower byte is assumed to be 0 */
    }

    sum = (sum >> 16) + (sum & 0xffff);	/* add in carry   */
    sum += (sum >> 16);			/* maybe one more */

    return(sum);
}

/* compute IP checksum */
static u_short
ip_cksum(
    struct ip *pip,
    void *plast)
{
    u_short sum;
    
    if (PIP_ISV6(pip))
	return(0);		/* IPv6 has no header checksum */
    if (!PIP_ISV4(pip))
	return(1);		/* I have no idea! */


    /* quick sanity check, if the packet is truncated, pretend it's valid */
    if ((char *)plast < (char *)((char *)pip+IP_HL(pip)*4-1)) {
	return(0);
    }

    /* ... else IPv4 */
    sum = cksum(pip, IP_HL(pip)*4);
    return(sum);
}


/* is the IP checksum valid? */
Bool
ip_cksum_valid(
    struct ip *pip,
    void *plast)
{
    u_short sum;
/*     PrintRawDataHex("IP header",pip,plast); */

    sum = ip_cksum(pip,plast);

    return((sum == 0) || (sum == 0xffff));
}


/* compute the TCP checksum */
static u_short
tcp_cksum(
    struct ip *pip,
    struct tcphdr *ptcp,
    void *plast)
{
    u_long sum = 0;
    unsigned tcp_length = 0;

    /* verify version */
    if (!PIP_ISV4(pip) && !PIP_ISV6(pip)) {
	fprintf(stderr,"Internal error, tcp_cksum: neither IPv4 nor IPv6\n");
	exit(-1);
    }


    /* TCP checksum includes: */
    /* - IP source */
    /* - IP dest */
    /* - IP type */
    /* - TCP header length + TCP data length */
    /* - TCP header and data */

    if (PIP_ISV4(pip)) {
	/* quick sanity check, if the packet is fragmented,
	   pretend it's valid */
	/* Thu Jul  6, 2000 - bugfix, bad check */
	if (((ntohs(pip->ip_off) << 2) & 0xffff) != 0) {
	    /* both the offset AND the MF bit must be 0 */
	    /* (we shifted off the DF bit, which might be on) */
	    return(0);
	}

	/* 2 4-byte numbers, next to each other */
	sum += cksum(&pip->ip_src,4*2);

	/* type */
	sum += (u_short) pip->ip_p;

	/* length (TCP header length + TCP data length) */
	tcp_length = ntohs(pip->ip_len) - (4 * IP_HL(pip));
	sum += (u_short) tcp_length;
    } else /* if (PIP_ISV6(pip))*/  {
              
        /* Support for IPv6 checksums has been added on Aug31, 2001 
	 * and has not been thoroughly tested. - Avinash 
	 */

        int total_length = 0;  /* Total length of the extension headers */
        struct ipv6 *pip6 = (struct ipv6 *)pip;
       
        /* quick sanity check, it the packet is truncated,
	 * pertend it is valid.
	 */ 
        if(gettcp(pip, &ptcp, &plast) != 0)
	 return(0);
       
        /* Forming the pseudo-header */
        /* source address */
        sum += cksum(&pip6->ip6_saddr,16);
       
        /* Looking for the destination address.
	 * May be in the IPv6 header or the last address in the 
	 * routing header (if present)
	 */
       
        /* No extension headers, hence, routing header not present */
        if(pip6->ip6_nheader == IPPROTO_TCP) {
	   sum += cksum(&pip6->ip6_daddr,16);
	}
        /* Some extension headers present. Searching for routing header */
        else {
	   /* find the first header */
	   struct ipv6_ext *pipv6_ext = (struct ipv6_ext *)(pip6+1);

	   /* Searching for the routing header */
	   int ret = getroutingheader(pip, &pipv6_ext, &plast);
	   
	   if(!ret) {  /* Found the routing header */
	      if(pipv6_ext->ip6ext_len >= 2) { /* Sanity check */
		 char *daddr = (char *)((char *)pipv6_ext + 8 + ((pipv6_ext->ip6ext_len - 2) * 8));
		 sum += cksum(&daddr,16);
	      }
	      else {  /* Not a valid routing header */
		 return(-1);
	      }
	   }
	   else {  /* Routing header not found */
	      sum += cksum(&pip6->ip6_daddr,16);
	   }
	}
       
       /* Upper-Layer Packet Length */
       total_length = total_length_ext_headers(pip6);
       if(total_length >= 0)
	 tcp_length = pip6->ip6_lngth - total_length;
       else /* Unknown extension header seen */ 
	 return(-1);
       sum += (u_short) tcp_length;
       
       /* Next Header (Type) */
       sum += (u_short) IPPROTO_TCP;
    }
   
      
    /* quick sanity check, if the packet is truncated, pretend it's valid */
    if ((char *)plast < (char *)((char *)ptcp+tcp_length-1)) {
	return(0);
    }

    /* checksum the TCP header and data */
    sum += cksum(ptcp,tcp_length);

    /* roll down into a 16-bit number */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (u_short)(~sum & 0xffff);
}



/* compute the UDP checksum */
static u_short
udp_cksum(
    struct ip *pip,
    struct udphdr *pudp,
    void *plast)
{
    u_long sum = 0;
    unsigned udp_length;

    /* WARNING -- this routine has not been extensively tested */

    /* verify version */
    if (!PIP_ISV4(pip) && !PIP_ISV6(pip)) {
	fprintf(stderr,"Internal error, udp_cksum: neither IPv4 nor IPv6\n");
	exit(-1);
    }


    /* UDP checksum includes: */
    /* - IP source */
    /* - IP dest */
    /* - IP type */
    /* - UDP length field */
    /* - UDP header and data */

    if (PIP_ISV4(pip)) {
	/* 2 4-byte numbers, next to each other */
	sum += cksum(&pip->ip_src,4*2);

	/* type */
	sum += (u_short) pip->ip_p;

	/* UDP length */
	udp_length = ntohs(pudp->uh_ulen);
	sum += htons(pudp->uh_ulen);
    } else /* if (PIP_ISV6(pip))*/  {
              
        /* Support for IPv6 checksums has been added on Aug31, 2001 
	 * and has not been thoroughly tested. - Avinash 
	 */

        struct ipv6 *pip6 = (struct ipv6 *)pip;
             
        /* quick sanity check, it the packet is truncated,
	 * pertend it is valid.
	 */ 
        if(getudp(pip, &pudp, &plast) != 0)
	 return(0);
       
        /* Forming the pseudo-header */
        /* source address */
        sum += cksum(&pip6->ip6_saddr,16);
       
        /* Looking for the destination address.
	 * May be in the IPv6 header or the last address in the 
	 * routing header (if present)
	 */
       
        /* No extension headers, hence, routing header not present */
        if(pip6->ip6_nheader == IPPROTO_UDP) {
	   sum += cksum(&pip6->ip6_daddr,16);
	}
        /* Some extension headers present. Searching for routing header */
        else {
	   /* find the first header */
	   struct ipv6_ext *pipv6_ext = (struct ipv6_ext *)(pip6+1);

	   /* Searching for the routing header */
	   int ret = getroutingheader(pip, &pipv6_ext, &plast);
	   
	   if(!ret) {  /* Found the routing header */
	      if(pipv6_ext->ip6ext_len >= 2) { /* Sanity check */
		 char *daddr = (char *)((char *)pipv6_ext + 8 + ((pipv6_ext->ip6ext_len - 2) * 8));
		 sum += cksum(&daddr,16);
	      }
	      else {  /* Not a valid routing header */
		 return(-1);
	      }
	   }
	   else {  /* Routing header not found */
	      sum += cksum(&pip6->ip6_daddr,16);
	   }
	}
       
       /* Upper-Layer Packet Length */
	udp_length = ntohs(pudp->uh_ulen);
	sum += htons(pudp->uh_ulen);

       /* Next Header (Type) */
        sum += (u_short) IPPROTO_UDP;
    }
   
 
    /* quick sanity check, if the packet is truncated, pretend it's valid */
    if ((char *)plast < (char *)((char *)pudp+udp_length-1)) {
	return(0);
    }

    /* checksum the UDP header and data */
    sum += cksum(pudp,udp_length);

    /* roll down into a 16-bit number */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (u_short)(~sum & 0xffff);
}


/* is the TCP checksum valid? */
Bool
tcp_cksum_valid(
    struct ip *pip,
    struct tcphdr *ptcp,
    void *plast)
{
    return(tcp_cksum(pip,ptcp,plast) == 0);
}


/* is the UDP checksum valid? */
Bool
udp_cksum_valid(
    struct ip *pip,
    struct udphdr *pudp,
    void *plast)
{
    if (ntohs(pudp->uh_sum) == 0) {
	/* checksum not used */
	return(1);		/* valid */
    }
    
    return(udp_cksum(pip,pudp,plast) == 0);
}
