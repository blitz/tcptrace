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
static char const rcsid[] =
   "$Header$";

#ifdef LOAD_MODULE_RTTGRAPH

#include <limits.h>
#include "tcptrace.h"
#include "mod_rttgraph.h"


/* a histogram structure */
struct hist {
    u_long num_buckets;
    u_long num_samples;
    u_long *buckets;
    u_long z;
};


#define NUM_SLICES 10
struct hist3d {
    struct hist rtt;
    struct hist rtt_diff_slices[NUM_SLICES+1];
};


struct samples {
    u_long num_samples;
    u_long max_samples;
    u_short max;
    u_short min;
    u_short *samples;
};

/* what we keep for each tcb */
struct rtt_tcb {
    tcb *ptcb;
    struct samples samples;
};


/* info kept for each connection */
static struct rttgraph_info {
    tcp_pair *ptp;
    struct rtt_tcb a2b;
    struct rtt_tcb b2a;
    struct rttgraph_info *next;
} *rttgraphhead = NULL, *rttgraphtail = NULL;




/* local routines */
static struct rttgraph_info *MakeRttgraphRec();
static void MakeBuckets(struct hist *phist, u_int num_buckets);
static void AddSample(struct samples *psamp, u_short sample);
static void PlotHist(MFILE *f,struct hist *phist);
static void PlotOne(struct rttgraph_info *prttg);



/* Mostly as a module example, here's a plug in that records RTTGRAPH info */
int
rttgraph_init(
    int argc,
    char *argv[])
{
    int i;
    int enable=0;

    /* look for "-xrttgraph[N]" */
    for (i=1; i < argc; ++i) {
	if (!argv[i])
	    continue;  /* argument already taken by another module... */
	if (strncmp(argv[i],"-x",2) == 0) {
	    if (strncasecmp(argv[i]+2,"rttgraph",4) == 0) {
		/* I want to be called */
		enable = 1;
		printf("mod_rttgraph: Capturing RTTGRAPH traffic\n");
		argv[i] = NULL;
	    }
	}
    }

    if (!enable)
	return(0);	/* don't call me again */

    return(1);	/* TRUE means call rttgraph_read and rttgraph_done later */
}


static void
MakeBuckets(
    struct hist *phist,
    u_int num_buckets)
{
    u_long *new_ptr;

    ++num_buckets;  /* 0-based arrays */

    if (num_buckets <= phist->num_buckets)
	return;  /* nothing to do */

    /* round num_buckets up to multiple of 100 */
    if ((num_buckets % 100) != 0) {
	num_buckets = 100 * ((num_buckets+99)/100);
    }

    /* either create the space or expand it */
    if (phist->buckets) {
	new_ptr = ReallocZ(phist->buckets,
			   phist->num_buckets * sizeof(u_long),
			   num_buckets * sizeof(u_long));
    } else {
	new_ptr = MallocZ(num_buckets * sizeof(u_long));
    }

    /* remember what we did */
    phist->num_buckets = num_buckets;
    phist->buckets = new_ptr;
}



static void
AddSample(
    struct samples *psamp,
    u_short sample)
{

/*     printf("AddSample(%d) called\n", sample); */
    
    /* make sure we have enough space */
    if ((psamp->num_samples+2) > (psamp->max_samples)) {
	u_long new_samples = psamp->max_samples + 100;
	u_short *new_ptr;
	if (psamp->samples) {
	    new_ptr = ReallocZ(psamp->samples,
			       psamp->max_samples * sizeof(u_short),
			       new_samples * sizeof(u_short));
	} else {
	    new_ptr = MallocZ(new_samples * sizeof(u_short));
	}
	psamp->max_samples = new_samples;
	psamp->samples = new_ptr;
    }

    /* remember what we did */
    psamp->samples[psamp->num_samples++] = sample;
    if (sample > psamp->max)
	psamp->max = sample;
    if (sample < psamp->max)
	psamp->min = sample;
}


static struct rttgraph_info *
MakeRttgraphRec()
{
    struct rttgraph_info *prttg;

    prttg = MallocZ(sizeof(struct rttgraph_info));

    /* (...leave the samples pointer NULL until first needed) */
    prttg->a2b.samples.max_samples = 0;
    prttg->a2b.samples.max = 0; prttg->a2b.samples.min = USHRT_MAX;
    prttg->b2a.samples.max_samples = 0;
    prttg->b2a.samples.max = 0; prttg->b2a.samples.min = USHRT_MAX;

    /* chain it in (at the tail of the list) */
    if (rttgraphhead == NULL) {
	rttgraphhead = prttg;
	rttgraphtail = prttg;
    } else {
	rttgraphtail->next = prttg;
	rttgraphtail = prttg;
    }

    return(prttg);
}


void
rttgraph_read(
    struct ip *pip,		/* the packet */
    tcp_pair *ptp,		/* info I have about this connection */
    void *plast,		/* past byte in the packet */
    void *mod_data)		/* module specific info for this connection */
{
    struct tcphdr *ptcp;
    struct rttgraph_info *prttg = mod_data;
    struct rtt_tcb *prtcb;
    tcb *ptcb;
    double rtt_us;
    u_long rtt_ms;

    /* find the start of the TCP header */
    ptcp = (struct tcphdr *) ((char *)pip + 4*IP_HL(pip));

    /* make sure there we could have a RTT sample */
    if (!ACK_SET(ptcp))
	return;  /* no RTT info */

    /* see which direction it is, if we don't know yet */
    ptcb = ptp2ptcb(ptp,pip,ptcp);
    if (ptcb == prttg->a2b.ptcb)
	prtcb = &prttg->a2b;
    else if (ptcb == prttg->b2a.ptcb)
	prtcb = &prttg->b2a;
    else {
	fprintf(stderr,
		"rttgraph_read: INTERNAL error (can't kind tcb)!!\n");
	exit(1);
    }

    /* grab the RTT */
    rtt_us = prtcb->ptcb->rtt_last;
    if (rtt_us == 0.0)
	return;  /* not a valid sample */

    /* convert to ms buckets */
    rtt_ms = (u_long) (rtt_us / 1000.0);

    if (debug && (rtt_ms == 0))
	printf("rtt_ms is 0, rtt_us was %f\n", rtt_us);

    /* add in the sample RTT */
    AddSample(&prtcb->samples, rtt_ms);
}


static void
DoHist(
    struct samples *psamp)
{
    int i;
    struct hist3d hist3d;
    MFILE *f;
    u_long sum;
    int slice;
    int base_z;
    int slice_size;

    if (psamp->num_samples == 0)
	return;

    printf("Samples: %lu\n", psamp->num_samples);
    printf("Min: %u\n", psamp->min);
    printf("Max: %u\n", psamp->max);

    /* init */
    hist3d.rtt.num_buckets = 0;
    memset(&hist3d.rtt,'\00',sizeof(struct hist));
    MakeBuckets(&hist3d.rtt, psamp->num_samples);
    for (i=0; i < NUM_SLICES; ++i) {
	memset(&hist3d.rtt_diff_slices[i],'\00',sizeof(struct hist));
        MakeBuckets(&hist3d.rtt_diff_slices[i], psamp->num_samples);
    }

    /* calculate the global histogram */
    for (i=0; i < psamp->num_samples; ++i) {
	u_short rtt = psamp->samples[i];

	++hist3d.rtt.buckets[rtt];
	++hist3d.rtt.num_samples;
    }
    

    /* find the slices, same amount of data in each slice */
    sum = 0;
    slice = 0;
    base_z = 0;
    slice_size = psamp->num_samples / NUM_SLICES;
    for (i=0; i < psamp->num_samples; ++i) {
	u_short count = hist3d.rtt.buckets[i];

	sum += count;

	if (sum > slice_size) {
	    hist3d.rtt_diff_slices[slice].z = base_z;
	    ++slice;
	    sum = 0;
	    base_z = i+1;
	}
    }
    for (; slice < NUM_SLICES; ++slice)
	hist3d.rtt_diff_slices[slice].z = ULONG_MAX;


    /* add the slice data */
    for (i=1; i < psamp->num_samples; ++i) {
	u_short rtt = psamp->samples[i];
	u_short prev_rtt = psamp->samples[i-1];

	/* see which slice holds the prev_rtt */ 
	for (slice = NUM_SLICES-1; slice >= 0; --slice) {
	    if (prev_rtt > hist3d.rtt_diff_slices[slice].z)
		break;
	}

	++hist3d.rtt_diff_slices[slice].buckets[rtt];
	++hist3d.rtt_diff_slices[slice].num_samples;
    }


    if ((f = Mfopen("rtt.dat","w")) == NULL) {
	perror("rtt.dat");
	exit (1);
    }
    printf("Total Histogram\n");
    hist3d.rtt.z = -1;
    PlotHist(f,&hist3d.rtt);
    Mfclose(f);

    if ((f = Mfopen("rtt3d.dat","w")) == NULL) {
	perror("rtt.dat");
	exit (1);
    }
    for (i=0; i < NUM_SLICES; ++i) {
	struct hist *phist = &hist3d.rtt_diff_slices[i];
	printf("Slice %d Histogram - base: %lu ms\n", i, phist->z);
	       
	PlotHist(f,phist);
    }

    /* plot the "connections" */
#ifdef BROKEN
    for (i=0; i < psamp->max; i+=10) {
	for (slice=0; slice < NUM_SLICES; ++slice) {
	    struct hist *phist = &hist3d.rtt_diff_slices[slice];
	    u_long count = phist->buckets[i];
	    float percent = (float)count / phist->num_samples;

	    if (phist->num_samples == 0)
		continue;

	    fprintf(f,"%4d %lu %.2f\n", i, phist->z, 100 * percent);
	}
	fprintf(f,"\n");
    }
#endif /* BROKEN */

    Mfclose(f);
}



static void
PlotHist(
    MFILE *f,
    struct hist *phist)
{
    int ms;
    int z = phist->z;

    if (phist->buckets == NULL)
	return;

    printf("  %lu samples\n", phist->num_samples);
    for (ms=0; ms < phist->num_buckets; ++ms) {
	u_long count = phist->buckets[ms];
	float percent;
       
	if (count == 0 || phist->num_samples == 0)
	    continue;

        percent = (float)count / phist->num_samples;
       
	printf("  %4d  %5lu  %5.2f\n", ms, count, 100 * percent);
	if (z == -1)
	    Mfprintf(f,"%4d  %.2f\n", ms, 100 * percent);
	else
	    Mfprintf(f,"%4d  %d %.2f\n", ms, z, 100 * percent);
    }
    Mfprintf(f,"\n");
}


static void
PlotOne(
    struct rttgraph_info *prttg)
{
    tcp_pair *ptp = prttg->ptp;

    printf("%s ==> %s (%s2%s)\n",
	   ptp->a_endpoint, ptp->b_endpoint,
	   ptp->a2b.host_letter, ptp->b2a.host_letter);
    DoHist(&prttg->a2b.samples);

    printf("%s ==> %s (%s2%s)\n",
	   ptp->b_endpoint, ptp->a_endpoint,
	   ptp->b2a.host_letter, ptp->a2b.host_letter);
    DoHist(&prttg->b2a.samples);
}



void
rttgraph_done(void)
{
    struct rttgraph_info *prttg;

    for (prttg=rttgraphhead; prttg; prttg=prttg->next) {
	PlotOne(prttg);
    }
}


void
rttgraph_usage(void)
{
    printf("\t-xrttgraph\tprint info about rttgraph traffic\n");
}


void *
rttgraph_newconn(
    tcp_pair *ptp)
{
    struct rttgraph_info *prttg;

    prttg = MakeRttgraphRec();

    prttg->ptp = ptp;
    prttg->a2b.ptcb = &ptp->a2b;
    prttg->b2a.ptcb = &ptp->b2a;

    return(prttg);
}

#endif /* LOAD_MODULE_RTTGRAPH */
