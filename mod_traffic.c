/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999
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
static char const rcsid[] =
   "$Header$";

#ifdef LOAD_MODULE_TRAFFIC

#include "tcptrace.h"
#include "mod_traffic.h"


/* info kept for each (active) port */
struct traffic_info {
    /* which port */
    u_short port;
    
    /* interval byte counters */
    PLINE line_nbytes;
    u_long nbytes;
    u_long ttlbytes;

    /* interval packet counters */
    PLINE line_npackets;
    u_long npackets;
    u_long ttlpackets;

    /* active connections */
    PLINE line_nactive;
    u_long nactive;
    u_long ttlactive;

    /* idle connections */
    PLINE line_nidle;
    u_long nidle;
    u_long ttlidle;

    /* open connections */
    PLINE line_nopen;
    u_long nopen;
    u_long ttlopen;

    /* instantaneous open connections */
    PLINE line_niopen;
    u_long n_i_open;
    u_long ttl_i_open;

    /* long-duration connections */
    PLINE line_nlong;
    u_long nlong;
    u_long ttllong;

    /* pureacks */
    PLINE line_pureacks;
    u_long npureacks;
    u_long ttlpureacks;

    /* which color is used for plotting */
    char *color;

    /* linked list of the one's we're using */
    struct traffic_info *next;
};
static struct traffic_info *traffichead = NULL;
#define NUM_PORTS 65536
static struct traffic_info **ports;  /* [NUM_PORTS] */
#define EXCLUDE_PORT ((void *)(-1))
#define INCLUDE_PORT (NULL)

/* name of the file that port data is dumped into */
#define PORT_FILENAME "traffic_byport.dat"

/* additional info kept per connection */
struct conn_info {
    Bool wasactive;		/* was this connection active over the interval? */
    Bool wasopen;		/* was this this connection EVER open? */
    Bool isopen;		/* is this connection open now? */
    Bool islong;		/* is this a long-duration connection? */
    Bool halfopen;		/* for half open conns */
    struct traffic_info *pti1;	/* pointer to the port info for this one */
    struct traffic_info *pti2;	/* pointer to the port info for this one */
    struct conn_info *next;	/* next in the chain */

    u_int last_dupacks;		/* last value of dupacks I saw */
    u_int last_rexmits;		/* last value of rexmits I saw */
    u_int last_rtts;		/* last value of rtt counters I saw */
};
static struct conn_info *connhead = NULL;



/* plotter files that we keep open */
static PLOTTER plotter_bytes;
static PLOTTER plotter_packets;
static PLOTTER plotter_active;
static PLOTTER plotter_idle;
static PLOTTER plotter_open;
static PLOTTER plotter_openclose;
static PLOTTER plotter_i_open;
static PLOTTER plotter_loss;
static PLOTTER plotter_long;
static PLOTTER plotter_rtt;
static PLOTTER plotter_halfopen;
static PLOTTER plotter_pureacks;

#define  PLOTTER_BYTES_FILENAME		"traffic_bytes.xpl"
#define  PLOTTER_PACKETS_FILENAME	"traffic_packets.xpl"
#define  PLOTTER_ACTIVE_FILENAME	"traffic_active.xpl"
#define  PLOTTER_OPEN_FILENAME		"traffic_open.xpl"
#define  PLOTTER_OPENCLOSE_FILENAME	"traffic_openclose.xpl"
#define  PLOTTER_I_OPEN_FILENAME	"traffic_i_open.xpl"
#define  PLOTTER_LOSS_FILENAME		"traffic_loss.xpl"
#define  PLOTTER_LONG_FILENAME		"traffic_long.xpl"
#define  PLOTTER_RTT_FILENAME		"traffic_rtt.xpl"
#define  PLOTTER_HALFOPEN_FILENAME	"traffic_halfopen.xpl"
#define  PLOTTER_PUREACKS_FILENAME	"traffic_pureacks.xpl"
#define  PLOTTER_IDLE_FILENAME		"traffic_idle.xpl"

/* argument flags */
static float age_interval = 15.0;  /* 15 seconds by default */
static Bool doplot_bytes = FALSE;
static Bool doplot_packets = FALSE;
static Bool doplot_active = FALSE;
static Bool doplot_open = FALSE;
static Bool doplot_openclose = FALSE;
static Bool doplot_i_open = FALSE;
static Bool doplot_loss = FALSE;
static Bool doplot_long = FALSE;
static Bool doplot_rtt = FALSE;
static Bool doplot_halfopen = FALSE;
static Bool doplot_pureacks = FALSE;
static Bool doplot_idle = FALSE;
static int longconn_duration = 60;


/* local routines */
static struct traffic_info *MakeTrafficRec(u_short port);
static void MakeTrafficLines(struct traffic_info *pti);
static struct conn_info *MakeConnRec(void);
static void AgeTraffic(void);
static struct traffic_info *FindPort(u_short port);
static void IncludePorts(unsigned firstport, unsigned lastport);
static void ExcludePorts(unsigned firstport, unsigned lastport);
static void CheckPortNum(unsigned portnum);
static char *PortName(int port);
static void ParseArgs(char *argstring);
static void DoplotIOpen(int port, Bool fopen);


/* info for opens and closes graphs */
static PLINE line_num_closes;
static PLINE line_num_opens;
static PLINE line_open_conns;
static PLINE line_num_halfopens;
static int num_closes = 0;
static int num_opens = 0;
static int open_conns = 0;
static int num_halfopens = 0;

/* info for the loss events graph */
static PLINE line_dupacks;
static PLINE line_rexmits;
static int dupacks;
static int rexmits;

/* info for the RTT graph */
static PLINE line_rtt_avg;
static PLINE line_rtt_min;
static PLINE line_rtt_max;
static float rtt_ttl;		/* in msecs */
static int rtt_min = -1;	/* in msecs */
static int rtt_max = -1;	/* in msecs */
static int rtt_samples;
static u_int rtt_minvalid = 0;	/* minimum RTT to consider (ms) */
static u_int rtt_maxvalid = 0xffffffff; /* maximum RTT to consider (ms) */


/* local debugging flag */
static int debug = 0;


static void
CheckPortNum(
    unsigned portnum)
{
    if ((portnum <= 0) || (portnum >= NUM_PORTS)) {
	fprintf(stderr,"mod_traffic: Invalid port number '%d'\n", portnum);
	traffic_usage();
	exit(-1);
    }
}


static void
ExcludePorts(
    unsigned firstport,
    unsigned lastport)
{
    CheckPortNum(firstport);
    CheckPortNum(lastport);

    if (debug)
	printf("mod_traffic: excluding ports [%d-%d]\n", firstport, lastport);

    while (firstport <= lastport)
	ports[firstport++] = EXCLUDE_PORT;
}


static void
IncludePorts(
    unsigned firstport,
    unsigned lastport)
{
    CheckPortNum(firstport);
    CheckPortNum(lastport);

    if (debug)
	printf("mod_traffic: including ports [%d-%d]\n", firstport, lastport);

    while (firstport <= lastport)
	ports[firstport++] = INCLUDE_PORT;
}



/* Mostly as a module example, here's a plug in that records TRAFFIC info */
int
traffic_init(
    int argc,
    char *argv[])
{
    int i;
    int enable=0;
    char *args = NULL;

    for (i=1; i < argc; ++i) {
	if (!argv[i])
	    continue;  /* argument already taken by another module... */
	if (strncmp(argv[i],"-x",2) == 0) {
	    if (strncasecmp(argv[i]+2,"traffic",sizeof("traffic")-1) == 0) {
		/* I want to be called */
		args = argv[i]+(sizeof("-xtraffic")-1);
		enable = 1;
		printf("mod_traffic: characterizing traffic\n");
		argv[i] = NULL;
	    }
	}
    }

    if (!enable)
	return(0);	/* don't call me again */

    /* init the data storage structure */
    ports = MallocZ(NUM_PORTS*sizeof(struct traffic_info *));

    ports[0] = MakeTrafficRec(0);

    /* parse the encoded args */
    ParseArgs(args);

    /* open the output files */
    if (doplot_packets)
	plotter_packets =
	    new_plotter(NULL,
			PLOTTER_PACKETS_FILENAME,
			"packets per second over time by port",
			"time","packets/second",
			NULL);
    if (doplot_bytes)
	plotter_bytes =
	    new_plotter(NULL,
			PLOTTER_BYTES_FILENAME,
			"bytes per second over time by port",
			"time","bytes/second",
			NULL);
    if (doplot_active)
	plotter_active =
	    new_plotter(NULL,
			PLOTTER_ACTIVE_FILENAME,
			"active connections over time by port",
			"time","active connections",
			NULL);
    if (doplot_idle)
	plotter_idle =
	    new_plotter(NULL,
			PLOTTER_IDLE_FILENAME,
			"idle connections over time by port",
			"time","idle connections",
			NULL);
    if (doplot_open)
	plotter_open =
	    new_plotter(NULL,
			PLOTTER_OPEN_FILENAME,
			"open connections over time by port",
			"time","open connections",
			NULL);
    if (doplot_i_open)
	plotter_i_open =
	    new_plotter(NULL,
			PLOTTER_I_OPEN_FILENAME,
			"open connections over time by port - instantaneous",
			"time","number of connections",
			NULL);
    if (doplot_openclose) {
	plotter_openclose =
	    new_plotter(NULL,
			PLOTTER_OPENCLOSE_FILENAME,
			"connections opened and closed over time",
			"time","number of connections",
			NULL);
	line_num_opens = new_line(plotter_openclose, "Number Opens", "green");
	line_num_closes = new_line(plotter_openclose, "Number Closes", "red");
	line_open_conns = new_line(plotter_openclose, "Total Open", "blue");
    }
    if (doplot_halfopen) {
	plotter_halfopen =
	    new_plotter(NULL,
			PLOTTER_HALFOPEN_FILENAME,
			"half open connections over time",
			"time","number of half open connections",
			NULL);
	line_num_halfopens = new_line(plotter_halfopen,
				      "Halfopen Conns", "green");
    }
    if (doplot_pureacks) {
	plotter_pureacks =
	    new_plotter(NULL,
			PLOTTER_PUREACKS_FILENAME,
			"pure acks (no data) per second over time",
			"time","pureacks/second",
			NULL);
    }

    if (doplot_loss) {
	plotter_loss =
	    new_plotter(NULL,
			PLOTTER_LOSS_FILENAME,
			"packet loss per second over time",
			"time","events/second",
			NULL);
	line_dupacks = new_line(plotter_loss, "Triple Dupacks", "yellow");
	line_rexmits = new_line(plotter_loss, "Retransmits", "blue");
    }

    if (doplot_rtt) {
	plotter_rtt =
	    new_plotter(NULL,
			PLOTTER_RTT_FILENAME,
			"RTT over time",
			"time","RTT (msecs)",
			NULL);
	line_rtt_min = new_line(plotter_rtt, "Min RTT", "green");
	line_rtt_max = new_line(plotter_rtt, "Max RTT", "red");
	line_rtt_avg = new_line(plotter_rtt, "Average RTT", "blue");
    }

    if (doplot_long) {
	char title[100];
	sprintf(title,"connections still open after %d seconds\n",
		longconn_duration);
	plotter_long =
	    new_plotter(NULL,
			PLOTTER_LONG_FILENAME,
			title,
			"time","number of connections",
			NULL);
    }

    /* we don't want the normal output */
    printsuppress = TRUE;

    /* create any lines that I want to draw */
    MakeTrafficLines(ports[0]);

    /* init the graphs and etc... */
    AgeTraffic();

    return(1);	/* TRUE means call traffic_read and traffic_done later */
}


/* return the record for traffic on this port */
static struct traffic_info *
FindPort(
    u_short port)
{
    struct traffic_info *pti;

    /* port "0" means "all", but we don't need to treat it as a special case */

    /* see what's there now */
    pti = ports[port];

    /* see if it's "excluded" */
    if ((port != 0) && (pti == EXCLUDE_PORT))
	return(NULL);

    /* make a new one if there's a NULL there */
    if (!pti) {
	pti = MakeTrafficRec(port);
	/* create any lines that I want to draw */
	MakeTrafficLines(pti);
    }

    return(pti);
}





static struct traffic_info *
MakeTrafficRec(
    u_short port)
{
    struct traffic_info *pti;

    pti = MallocZ(sizeof(struct traffic_info));

    if (debug>10)
	printf("MakeTrafficRec(%d) called\n", (int)port);

    /* init */
    pti->port = port;

    /* chain it in (at head of list) */
    pti->next = traffichead;
    traffichead = pti;

    /* add to lookup array */
    ports[port] = pti;

    return(pti);
}


static void
MakeTrafficLines(
    struct traffic_info *pti)
{
    char *portname;
    static int nextcolor = 0;

    /* map port number to name for printing */
    portname = (pti->port==0)?"total":strdup(PortName(pti->port));

    /* pick color */
    pti->color = ColorNames[nextcolor % NCOLORS];
    ++nextcolor;

    /* create the lines that we sometimes use */
    if (doplot_bytes)
	pti->line_nbytes = new_line(plotter_bytes, portname, pti->color);
    if (doplot_packets) 
	pti->line_npackets = new_line(plotter_packets, portname, pti->color);
    if (doplot_active)
	pti->line_nactive = new_line(plotter_active, portname, pti->color);
    if (doplot_idle)
	pti->line_nidle = new_line(plotter_idle, portname, pti->color);
    if (doplot_open)
	pti->line_nopen = new_line(plotter_open, portname, pti->color);
    if (doplot_long)
	pti->line_nlong = new_line(plotter_long, portname, pti->color);
    if (doplot_i_open)
	pti->line_niopen = new_line(plotter_i_open, portname, pti->color);
    if (doplot_pureacks)
	pti->line_pureacks = new_line(plotter_pureacks, portname, pti->color);
}



static struct conn_info *
MakeConnRec(void)
{
    struct conn_info *pci;

    pci = MallocZ(sizeof(struct conn_info));

    /* chain it in (at head of list) */
    pci->next = connhead;
    connhead = pci;

    return(pci);
}


void
traffic_read(
    struct ip *pip,		/* the packet */
    tcp_pair *ptp,		/* info I have about this connection */
    void *plast,		/* past byte in the packet */
    void *mod_data)		/* connection info for this one */
{
    struct tcphdr *ptcp = (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);
    struct traffic_info *pti1 = FindPort(ptcp->th_sport);
    struct traffic_info *pti2 = FindPort(ptcp->th_dport);
    u_long bytes = ntohs(pip->ip_len);
    static timeval last_time = {0,0};
    struct conn_info *pci = mod_data;

    /* if neither port is interesting, then ignore this one */
    if (!pti1 && !pti2) {
	return;
    }

    /* OK, this connection is now active */
    pci->wasactive = 1;

    /* check to see if it's really "open" (traffic in both directions) */
    if (!pci->wasopen) {
	if ((ptp->a2b.packets > 0) && (ptp->b2a.packets > 0)) {
	    /* bidirectional: OK, we'll call it open */
	    pci->wasopen = 1;
	    pci->isopen = 1;
	    ++num_opens;
	    ++open_conns;

	    /* instantaneous opens and closes */
	    if (doplot_i_open) {
		DoplotIOpen(ptcp->th_dport, TRUE);
		DoplotIOpen(ptcp->th_sport, TRUE);
		DoplotIOpen(0, TRUE);
	    }
	}
    }

    /* add to port-specific counters */
    if (pti1) {
	pti1->nbytes += bytes;
	pti1->npackets += 1;
    }
    if (pti2) {
	pti2->nbytes += bytes;
	pti2->npackets += 1;
    }

    /* add to GLOBAL counters */
    ports[0]->nbytes += bytes;
    ports[0]->npackets += 1;
    ports[0]->npureacks += 1;

    /* see if we're closing it */
    if (RESET_SET(ptcp) ||
	(FIN_SET(ptcp) &&	/* find in BOTH directions */
	 ((ptp->a2b.fin_count>0) && (ptp->b2a.fin_count>0)))) {
	if (pci->isopen) {
	    pci->isopen = 0;
	    ++num_closes;
	    --open_conns;

	    /* instantaneous opens and closes */
	    if (doplot_i_open) {
		DoplotIOpen(ptcp->th_dport, FALSE);
		DoplotIOpen(ptcp->th_sport, FALSE);
		DoplotIOpen(0, FALSE);
	    }
	}
    }

    /* half open conns */
    if (FIN_SET(ptcp)) {
	if ((ptp->a2b.fin_count>0) && (ptp->b2a.fin_count>0)) {
	    if (pci->halfopen) {
		/* fully closed now */
		--num_halfopens;
		pci->halfopen = 0;
	    }
	} else if (!pci->halfopen) {
		/* half open now */
		++num_halfopens;
		pci->halfopen = 1;
	}
    }

    /* check losses */
    if (pci->last_dupacks != ptp->a2b.rtt_triple_dupack+
	ptp->b2a.rtt_triple_dupack) {
	pci->last_dupacks = ptp->a2b.rtt_triple_dupack+
	    ptp->b2a.rtt_triple_dupack;
	++dupacks;
    }
    if (pci->last_rexmits != ptp->a2b.rexmit_pkts+ptp->b2a.rexmit_pkts) {
	pci->last_rexmits = ptp->a2b.rexmit_pkts+ptp->b2a.rexmit_pkts;
	++rexmits;
    }

    /* RTT stats */
    if (doplot_rtt && (ACK_SET(ptcp))) {
	tcb *ptcb;
	int rtt;

	/* see which of the 2 TCB's this goes with */
	if (ptp->addr_pair.a_port == ptcp->th_dport)
	    ptcb = &ptp->a2b;
	else
	    ptcb = &ptp->b2a;

	/* check the rtt counter of the last sample */
	rtt = ptcb->rtt_last / 1000.0;
 
	if ((pci->last_rtts != ptcb->rtt_count + ptcb->rtt_amback) &&
	    (ptcb->rtt_last != 0.0) &&
	    (rtt > rtt_minvalid) && (rtt <= rtt_maxvalid)) {

	    /* sample is only valid when one of these counters is higher */
	    pci->last_rtts = ptcb->rtt_count + ptcb->rtt_amback;

	    /* keep stats */
	    rtt_ttl += rtt;
	    ++rtt_samples;

	    /* also, remember min and max */
	    if ((rtt_max == -1) || (rtt_max < rtt))
		rtt_max = rtt;
	    if ((rtt_min == -1) || (rtt_min > rtt))
		rtt_min = rtt;

	    if (debug > 9)
		printf("Rtt: %d,  min:%d,  max:%d\n",
		       rtt, rtt_min, rtt_max);
	}
    }


    /* see if this is now "long duration" */
    if (!pci->islong) {
	int etime_msecs = elapsed(ptp->first_time,current_time);
	if (etime_msecs/1000000 > longconn_duration) {
	    pci->islong = 1;
	}
    }

    /* count "pure acks" (no data) */
    if (ACK_SET(ptcp)) {
	int tcp_length, tcp_data_length;
	tcp_length = getpayloadlength(pip, plast);
	tcp_data_length = tcp_length - (4 * ptcp->th_off);
	if (tcp_data_length == 0) {
	    if (pti1) {
		++pti1->npureacks;
	    }
	    if (pti2) {
		++pti2->npureacks;
	    }
	}
    }


    /* determine elapsed time and age the samples */
    if (elapsed(last_time,current_time)/1000000.0 > age_interval) {
	AgeTraffic();
	last_time = current_time;
    }
}


static char *
PortName(
    int port)
{
    static char buf[20];

    if (port == 0)
	return("total");

    sprintf(buf,"%d",port);
    return(buf);
}


static void
AgeTraffic(void)
{
    struct traffic_info *pti;
    struct conn_info *pci;
    static timeval last_time = {0,0};
    float etime;
    int ups;			/* units per second */

    /* first time doesn't count */
    if (ZERO_TIME(&last_time)) {
	last_time = current_time;
	return;
    }

    /* check elapsed time */
    etime = elapsed(last_time, current_time);
    if (debug>1)
	printf("AgeTraffic called, elapsed time is %.3f seconds\n", etime/1000000);
    if (etime == 0.0)
	return;

    /* roll the open/active/long connections into the port records */
    for (pci=connhead; pci; pci=pci->next) {
	if (pci->wasactive) {
	    if (pci->pti1)
		++pci->pti1->nactive;
	    if (pci->pti2)
		++pci->pti2->nactive;
	    pci->wasactive = 0;
	    ++ports[0]->nactive;
	}
	if (pci->isopen) {
	    if (pci->pti1)
		++pci->pti1->nopen;
	    if (pci->pti2)
		++pci->pti2->nopen;
	    ++ports[0]->nopen;
	    if (pci->islong) {
		if (pci->pti1)
		    ++pci->pti1->nlong;
		if (pci->pti2)
		    ++pci->pti2->nlong;
		++ports[0]->nlong;
	    }

	    if (!pci->wasactive) {
		/* open and !active ==> IDLE */
		if (pci->pti1)
		    ++pci->pti1->nidle;
		if (pci->pti2)
		    ++pci->pti2->nidle;
		++ports[0]->nidle;
	    }
	}
    }
    

    /* ============================================================ */
    /* plot halfopen conns */
    if (doplot_halfopen) {
	/* draw lines */
	extend_line(line_num_halfopens,current_time, num_halfopens);
    }


    /* ============================================================ */
    /* plot connection activity */
    /* opens */
    if (doplot_openclose) {
	/* draw lines */
	extend_line(line_num_opens,current_time, num_opens);
	extend_line(line_num_closes,current_time, num_closes);
	extend_line(line_open_conns,current_time, open_conns);

	/* reset interval counters */
	num_opens = 0;
	num_closes = 0;
    }


    /* ============================================================ */
    /* report of loss events */
    if (doplot_loss) {
	/* convert to events/second */
	dupacks = (int)((float)dupacks/age_interval);
	rexmits = (int)((float)rexmits/age_interval);

	/* draw lines */
	extend_line(line_dupacks,current_time, dupacks);
	extend_line(line_rexmits,current_time, rexmits);

	/* reset interval counters */
	dupacks = 0;
	rexmits = 0;
    }


    /* ============================================================ */
    /* report of RTT */
    if (doplot_rtt && (rtt_samples > 0)) {
	int rtt_avg;

	/* convert to average rtt */
	rtt_avg = (int)((rtt_ttl/(float)rtt_samples));

	/* draw lines */
	extend_line(line_rtt_avg, current_time, rtt_avg);
	if (rtt_min != -1)
	    extend_line(line_rtt_min, current_time, rtt_min);
	if (rtt_max != -1)
	    extend_line(line_rtt_max, current_time, rtt_max);

	/* reset interval counters */
	rtt_ttl = 0;
	rtt_samples = 0;
	rtt_min = -1;
	rtt_max = -1;
    }


    /* ============================================================ */
    /* print them out */
    for (pti=traffichead; pti; pti=pti->next) {
	if (debug>1)
	    printf("  Aging Port %u   bytes: %lu  packets: %lu\n",
		   pti->port, pti->nbytes, pti->npackets);

	/* plot bytes */
	if (doplot_bytes) {
	    /* convert to units per second */
	    ups = (int)((float)pti->nbytes * 1000000.0 / etime);

	    /* plot it */
	    extend_line(pti->line_nbytes,current_time, ups);
	}

	/* plot packets */
	if (doplot_packets) {
	    /* convert to units per second */
	    ups = (int)((float)pti->npackets * 1000000.0 / etime);

	    /* plot it */
	    extend_line(pti->line_npackets,current_time, ups);
	}


	/* plot active connections */
	if (doplot_active) {
	    /* plot it */
	    extend_line(pti->line_nactive,current_time, pti->nactive);
	}

	/* plot idle connections */
	if (doplot_idle) {
	    /* plot it */
	    extend_line(pti->line_nidle,current_time, pti->nidle);
	}


	/* plot open connections */
	if (doplot_open) {
	    /* plot it */
	    extend_line(pti->line_nopen,current_time, pti->nopen);
	}

	/* plot long-duration */
	if (doplot_long) {
	    extend_line(pti->line_nlong,current_time, pti->nlong);
	}

	/* plot pureacks */
	if (doplot_pureacks) {
	    /* convert to units per second */
	    ups = (int)((float)pti->npureacks * 1000000.0 / etime);

	    extend_line(pti->line_pureacks, current_time, ups);
	}
    }

    /* zero them out */
    for (pti=traffichead; pti; pti=pti->next) {
	pti->ttlbytes += pti->nbytes;
	pti->ttlpackets += pti->npackets;
	pti->ttlpureacks += pti->npureacks;

	pti->nbytes = 0;
	pti->nlong = 0;
	pti->npackets = 0;
	pti->nactive = 0;
	pti->nidle = 0;
	pti->nopen = 0;
	pti->npureacks = 0;
    }

    last_time = current_time;
}


void	
traffic_done(void)
{
    struct traffic_info *pti;
    struct conn_info *pci;
    MFILE *pmf;
    int i;

    /* roll the active connections into the port records */
    for (pci=connhead; pci; pci=pci->next) {
	if (pci->pti1)
	    ++pci->pti1->ttlactive;
	if (pci->pti2)
	    ++pci->pti2->ttlactive;
	++ports[0]->ttlactive;
    }

    AgeTraffic();

    pmf = Mfopen(PORT_FILENAME,"w");
    printf("Dumping port statistics into file %s\n", PORT_FILENAME);

    /* dump out the data */
    Mfprintf(pmf,"Overall totals by port\n");
    for (i=0; i < NUM_PORTS; ++i) {
	pti = ports[i];
	if ((pti != EXCLUDE_PORT) && (pti != INCLUDE_PORT)) {
	    if (i == 0)
		Mfprintf(pmf,"Port TTL ");
	    else
		Mfprintf(pmf,"Port %5u   ", pti->port);
	    Mfprintf(pmf,"bytes: %12lu  packets: %10lu  connections: %8lu\n",
		     pti->ttlbytes, pti->ttlpackets, pti->ttlactive);
	}
    }

    Mfclose(pmf);

    printf("Plotting performed at %.3f second intervals\n", age_interval);
}




void *
traffic_newconn(
    tcp_pair *ptp)
{
    struct conn_info *pci;

    pci = MakeConnRec();
    pci->pti1 = FindPort(ptp->addr_pair.a_port);
    pci->pti2 = FindPort(ptp->addr_pair.b_port);

    return(pci);
}


void
traffic_usage(void)
{
    printf("\t-xtraffic\"[ARGS]\"\tprint info about overall traffic\n");
    printf("\
\t   module argument format:\n\
\t       -iS          set statistics interval to S (float) seconds, default 15.0\n\
\t       -pP          include information on port P\n\
\t       -pP1-P2      include information on ports in the range [P1-P2]\n\
\t       -p-P         exclude information on port P\n\
\t       -p-P1-P2     exclude information on ports in the range [P1-P2]\n\
\t       -pSPEC,SPEC  commas chain together specs\n\
\t       -G           generate all graphs\n\
\t       -A           generate the 'active connections' graph\n\
\t       -B           generate the 'bytes per second' graph\n\
\t       -C           generate the 'opens and closes' graph\n\
\t       -H           generate the 'halfopen connections' graph\n\
\t       -K           generate the 'pure acKs/second' graph\n\
\t       -L           generate the 'losses per second' graph\n\
\t       -O           generate the 'open connections' graph\n\
\t       -I           generate the 'instantaneous open connections' graph\n\
\t       -P           generate the 'packets per second' graph\n\
\t       -Q           generate the 'idle (Quiet) connections' graph\n\
\t       -R[MIN[-MAX]]generate the 'round trip time' graph\n\
\t                    with args, ignore samples outside MIN to MAX (in ms)\n\
\t       -D[SECS]     generate the 'long duration connection' graph\n\
\t		      default definition of 'long' is 60 seconds\n\
\t       -d           enable local debugging in this module\n\
\t     Examples\n\
\t       -xtraffic\" -p23\"            only port 23\n\
\t       -xtraffic\" -p1-1023\"        only ports 1-1023\n\
\t       -xtraffic\"-p1-1023,-10-20 -L -O\"  only ports 1-1023, but exclude ports 10-20\n\
\t     With no ports specification, all ports are gathered.  With ANY\n\
\t     spec, all ports are initially EXCLUDED\n\
");
}

static void
ParseArgs(char *argstring)
{
    int argc;
    char **argv;
    static int excluded = 0;
    int i;
    char *pch;
    
    /* make sure there ARE arguments */
    if (!(argstring && *argstring))
	return;

    /* break the string into normal arguments */
    StringToArgv(argstring,&argc,&argv);

    /* check the module args */
    for (i=1; i < argc; ++i) {
	float interval;
	if (debug > 1)
	    printf("Checking argv[%d]: '%s'\n", i, argv[i]);
	if (strcmp(argv[i],"-d") == 0) {
	    ++debug;
	} else if (sscanf(argv[i],"-i%f", &interval) == 1) {
	    age_interval = interval;
	    if (debug)
		printf("mod_traffic: setting age interval to %.3f seconds\n",
		       age_interval);
	} else if (strcmp(argv[i],"-G") == 0) {
	    doplot_active = TRUE;
	    doplot_idle = TRUE;
	    doplot_bytes = TRUE;
	    doplot_loss = TRUE;
	    doplot_long = TRUE;
	    doplot_open = TRUE;
	    doplot_halfopen = TRUE;
	    doplot_openclose = TRUE;
	    doplot_i_open = TRUE;
	    doplot_packets = TRUE;
	    doplot_pureacks = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating all graphs\n");
	} else if (strcmp(argv[i],"-A") == 0) {
	    doplot_active = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'active' graph into '%s'\n",
			PLOTTER_ACTIVE_FILENAME);
	} else if (strcmp(argv[i],"-B") == 0) {
	    doplot_bytes = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'bytes' graph into '%s'\n",
			PLOTTER_BYTES_FILENAME);
	} else if (strcmp(argv[i],"-H") == 0) {
	    doplot_halfopen = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'halfopen' graph into '%s'\n",
			PLOTTER_HALFOPEN_FILENAME);
	} else if (strcmp(argv[i],"-Q") == 0) {
	    doplot_idle = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'idle' graph into '%s'\n",
			PLOTTER_IDLE_FILENAME);
	} else if (strcmp(argv[i],"-K") == 0) {
	    doplot_pureacks = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'pureacks' graph into '%s'\n",
			PLOTTER_PUREACKS_FILENAME);
	} else if (strcmp(argv[i],"-L") == 0) {
	    doplot_loss = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'loss' graph into '%s'\n",
			PLOTTER_LOSS_FILENAME);
	} else if (strncmp(argv[i],"-D",2) == 0) {
	    doplot_long = TRUE;
	    if (strlen(argv[i]) > 2) {
		/* grab the number */
		longconn_duration = atoi(argv[i]+2);
		if (longconn_duration <= 0) {
		    fprintf(stderr,"bad time value for -LN '%s'\n",
			    argv[i]);
		    exit(-1);
		}

	    }
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'long duration' graph (%d secs) into '%s'\n",
			longconn_duration,
			PLOTTER_LONG_FILENAME);
	} else if (strcmp(argv[i],"-O") == 0) {
	    doplot_open = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'open' graph into '%s'\n",
			PLOTTER_OPEN_FILENAME);
	} else if (strcmp(argv[i],"-C") == 0) {
	    doplot_openclose = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'openclose' graph into '%s'\n",
			PLOTTER_OPENCLOSE_FILENAME);
	} else if (strcmp(argv[i],"-I") == 0) {
	    doplot_i_open = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'instantaneous openclose' graph into '%s'\n",
			PLOTTER_I_OPEN_FILENAME);
	} else if (strcmp(argv[i],"-P") == 0) {
	    doplot_packets = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'packets' graph into '%s'\n",
			PLOTTER_PACKETS_FILENAME);
	} else if (strncmp(argv[i],"-R",2) == 0) {
	    int nargs;
	    doplot_rtt = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'rtt' graph into '%s'\n",
			PLOTTER_RTT_FILENAME);
	    /* check for valid RTT range args */
	    nargs = sscanf(argv[i],"-R%d-%d", &rtt_minvalid,
			   &rtt_maxvalid);
	    switch (nargs) {
	      case 2: {		/* 2 args is min and max */
		  /* sanity check */
		  if (rtt_maxvalid <= rtt_minvalid) {
		      fprintf(stderr,
			      "mod_traffic: Out of order min-max range for -R '%s'\n",
			      argv[i]);
		      traffic_usage();
		      exit(-1);
		  }
		  break;
	      }
	      case 1: {		/* 1 args in min rtt */
		  /* sanity check */
		  if (rtt_maxvalid <= rtt_minvalid) {
		      fprintf(stderr,
			      "mod_traffic: Out of order min-max range for -R '%s'\n",
			      argv[i]);
		      traffic_usage();
		      exit(-1);
		  }
		  break;
	      }
	      case 0: 		/* no args, that's OK */
	      case -1: 		/* (means the same as 0) */
		break;
	      default:		/* illegal args  */
		fprintf(stderr,
			"mod_traffic: Invalid min-max range for -R '%s'\n",
			argv[i]);
		traffic_usage();
		exit(-1);
		break;
	    }
	} else if (strncmp(argv[i],"-p",2) == 0) {
	    pch = argv[i]+2;
	    while (pch && *pch) {
		char *pch_next;
		unsigned port1, port2;

		if ((pch_next = strchr(pch,',')) != NULL) {
		    *pch_next = '\00';
		    ++pch_next;
		}

		if (!excluded) {
		    ExcludePorts(1,NUM_PORTS-1);
		    excluded = 1;
		}

		if (sscanf(pch,"-%u-%u", &port1, &port2) == 2) {
		    ExcludePorts(port1,port2);
		} else if (sscanf(pch,"%u-%u", &port1, &port2) == 2) {
		    IncludePorts(port1,port2);
		} else if (sscanf(pch,"-%u", &port1) == 1) {
		    ExcludePorts(port1,port1);
		} else if (sscanf(pch,"%u", &port1) == 1) {
		    IncludePorts(port1,port1);
		} else {
		    fprintf(stderr,"mod_traffic: Invalid port specification string '%s'\n", pch);
		    traffic_usage();
		    exit(-1);
		}

		pch = pch_next;
	    }
	} else {
	    fprintf(stderr,"Traffic module: bad argument '%s'\n",
		    argv[i]);
	    exit(-1);
	}
    }
}

static void
DoplotIOpen(int port, Bool fopen)
{
    struct traffic_info *pti;

    /* just for this port */
    if ((pti = FindPort(port)) == NULL)
	return;

    if (fopen)
	++pti->n_i_open;
    else
	--pti->n_i_open;

    extend_line(pti->line_niopen, current_time, pti->n_i_open);
}

#endif /* LOAD_MODULE_TRAFFIC */
