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

/* locally global variables */
static int packet_count = 0;
static int search_count = 0;
static Bool *ignore_pairs = NULL;/* which ones will we ignore */
static Bool more_conns_ignored = FALSE;



/* provided globals  */
int num_udp_pairs = -1;	/* how many pairs we've allocated */
udp_pair **utp = NULL;	/* array of pointers to allocated pairs */
int max_udp_pairs = 64; /* initial value, automatically increases */
u_long udp_trace_count = 0;


/* local routine definitions */
static udp_pair *NewUTP(struct ip *, struct udphdr *);
static udp_pair *FindUTP(struct ip *, struct udphdr *, int *);
static void MoreUdpPairs(int num_needed);




static udp_pair *
NewUTP(
    struct ip *pip,
    struct udphdr *pudp)
{
    udp_pair *pup;

    /* make a new one, if possible */
    if ((num_udp_pairs+1) >= max_udp_pairs) {
	MoreUdpPairs(num_udp_pairs+1);
    }

    /* create a new UDP pair record and remember where you put it */
    ++num_udp_pairs;
    pup = utp[num_udp_pairs] = MallocZ(sizeof(udp_pair));


    /* grab the address from this packet */
    CopyAddr(&pup->addr_pair,
	     pip, ntohs(pudp->uh_sport), ntohs(pudp->uh_dport));

    /* data structure setup */
    pup->a2b.pup = pup;
    pup->b2a.pup = pup;
    pup->a2b.ptwin = &pup->b2a;
    pup->b2a.ptwin = &pup->a2b;

    /* fill in connection name fields */
    pup->a2b.host_letter = strdup(NextHostLetter());
    pup->b2a.host_letter = strdup(NextHostLetter());
    pup->a_hostname = strdup(HostName(pup->addr_pair.a_address));
    pup->a_portname = strdup(ServiceName(pup->addr_pair.a_port));
    pup->a_endpoint =
	strdup(EndpointName(pup->addr_pair.a_address,
			    pup->addr_pair.a_port));
    pup->b_hostname = strdup(HostName(pup->addr_pair.b_address));
    pup->b_portname = strdup(ServiceName(pup->addr_pair.b_port));
    pup->b_endpoint = 
	strdup(EndpointName(pup->addr_pair.b_address,
			    pup->addr_pair.b_port));

    pup->filename = cur_filename;

    return(pup);
}



/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
#define HASH_TABLE_SIZE 1021  /* oughta be prime */
static udp_pair *
FindUTP(
    struct ip *pip,
    struct udphdr *pudp,
    int *pdir)
{
    static udp_pair *pup_hashtable[HASH_TABLE_SIZE] = {NULL};
    udp_pair **ppup_head = NULL;
    udp_pair *pup;
    udp_pair *pup_last;
    udp_pair tp_in;
    int dir;
    hash hval;

    /* grab the address from this packet */
    CopyAddr(&tp_in.addr_pair, pip,
	     ntohs(pudp->uh_sport), ntohs(pudp->uh_dport));

    /* grab the hash value (already computed by CopyAddr) */
    hval = tp_in.addr_pair.hash % HASH_TABLE_SIZE;
    

    pup_last = NULL;
    ppup_head = &pup_hashtable[hval];
    for (pup = *ppup_head; pup; pup=pup->next) {
	++search_count;
	if (SameConn(&tp_in.addr_pair,&pup->addr_pair,&dir)) {
	    /* move to head of access list (unless already there) */
	    if (pup != *ppup_head) {
		pup_last->next = pup->next; /* unlink */
		pup->next = *ppup_head;	    /* move to head */
		*ppup_head = pup;
	    }
	    *pdir = dir;
	    return(pup);
	}
	pup_last = pup;
    }

    /* Didn't find it, make a new one, if possible */
    pup = NewUTP(pip,pudp);

    /* put at the head of the access list */
    if (pup) {
	pup->next = *ppup_head;
	*ppup_head = pup;
    }

    *pdir = A2B;
    return(pup);
}
     
 

udp_pair *
udpdotrace(
    struct ip *pip,
    struct udphdr *pudp,
    void *plast)
{
    udp_pair	*pup_save;
    ucb		*thisdir;
    ucb		*otherdir;
    udp_pair	tp_in;
    int		dir;
    u_short	uh_sport;	/* source port */
    u_short	uh_dport;	/* destination port */
    u_short	uh_ulen;	/* data length */

    /* make sure we have enough of the packet */
    if ((unsigned)pudp + sizeof(struct udphdr)-1 > (unsigned)plast) {
	if (warn_printtrunc)
	    fprintf(stderr,
		    "UDP packet %lu truncated too short to trace, ignored\n",
		    pnum);
	++ctrunc;
	return(NULL);
    }


    /* convert interesting fields to local byte order */
    uh_sport = ntohs(pudp->uh_sport);
    uh_dport = ntohs(pudp->uh_dport);
    uh_ulen = ntohs(pudp->uh_ulen);

    /* make sure this is one of the connections we want */
    pup_save = FindUTP(pip,pudp,&dir);

    ++packet_count;

    if (pup_save == NULL) {
	return(NULL);
    }

    ++udp_trace_count;

    /* do time stats */
    if (ZERO_TIME(&pup_save->first_time)) {
	pup_save->first_time = current_time;
    }
    pup_save->last_time = current_time;

    /* save to a file if requested */
    if (output_filename) {
	PcapSavePacket(output_filename,pip,plast);
    }

    /* now, print it if requested */
    if (printem && !printallofem) {
	printf("Packet %lu\n", pnum);
	printpacket(0,		/* original length not available */
		    (unsigned)plast - (unsigned)pip + 1,
		    NULL,0,	/* physical stuff not known here */
		    pip,plast);
    }

    /* grab the address from this packet */
    CopyAddr(&tp_in.addr_pair, pip,
	     uh_sport, uh_dport);

    /* figure out which direction this packet is going */
    if (dir == A2B) {
	thisdir  = &pup_save->a2b;
	otherdir = &pup_save->b2a;
    } else {
	thisdir  = &pup_save->b2a;
	otherdir = &pup_save->a2b;
    }


    /* do data stats */
    thisdir->packets += 1;
    thisdir->data_bytes += uh_ulen;


    /* total packets stats */
    ++pup_save->packets;
    ++thisdir->packets;

    return(pup_save);
}



void
udptrace_done(void)
{
    udp_pair *pup;
    int ix;
    double etime;

    if (!printsuppress) {
	if (udp_trace_count == 0) {
	    fprintf(stdout,"no traced UDP packets\n");
	    return;
	} else {
	    if ((tcp_trace_count > 0) && (!printbrief))
		printf("\n============================================================\n");
	    fprintf(stdout,"UDP connection info:\n");
	}
    }
	       
    if (!printbrief)
	fprintf(stdout,"%d UDP %s traced:\n",
		num_udp_pairs + 1,
		num_udp_pairs==0?"connection":"connections");

    /* elapsed time */
    etime = elapsed(first_packet,last_packet);

    if (ctrunc > 0) {
	fprintf(stdout,
		"*** %lu packets were too short to process at some point\n",
		ctrunc);
	if (!warn_printtrunc)
	    fprintf(stdout,"\t(use -w option to show details)\n");
    }
    if (debug>1)
	fprintf(stdout,"average search length: %d\n",
		search_count / packet_count);

    /* print each connection */
    if (!printsuppress) {
	for (ix = 0; ix <= num_udp_pairs; ++ix) {
	    pup = utp[ix];

	    if (printbrief) {
		fprintf(stdout,"%3d: ", ix+1);
		UDPPrintBrief(pup);
	    } else {
		if (ix > 0)
		    fprintf(stdout,"================================\n");
		fprintf(stdout,"UDP connection %d:\n", ix+1);
		UDPPrintTrace(pup);
	    }
	}
    }
}

static void
MoreUdpPairs(
    int num_needed)
{
    int new_max_udp_pairs;
    int i;

    if (num_needed < max_udp_pairs)
	return;

    new_max_udp_pairs = max_udp_pairs * 4;
    while (new_max_udp_pairs < num_needed)
	new_max_udp_pairs *= 4;
    
    if (debug)
	printf("trace: making more space for %d total UDP pairs\n",
	       new_max_udp_pairs);

    /* enlarge array to hold any pairs that we might create */
    utp = ReallocZ(utp,
		   max_udp_pairs * sizeof(udp_pair *),
		   new_max_udp_pairs * sizeof(udp_pair *));

    /* enlarge array to keep track of which ones to ignore */
    ignore_pairs = ReallocZ(ignore_pairs,
			    max_udp_pairs * sizeof(Bool),
			    new_max_udp_pairs * sizeof(Bool));
    if (more_conns_ignored)
	for (i=max_udp_pairs; i < new_max_udp_pairs;++i)
	    ignore_pairs[i] = TRUE;

    max_udp_pairs = new_max_udp_pairs;
}


void
udptrace_init(void)
{
    static Bool initted = FALSE;

    if (initted)
	return;

    initted = TRUE;

    /* create an array to hold any pairs that we might create */
    utp = (udp_pair **) MallocZ(max_udp_pairs * sizeof(udp_pair *));

    /* create an array to keep track of which ones to ignore */
    ignore_pairs = (Bool *) MallocZ(max_udp_pairs * sizeof(Bool));
}
