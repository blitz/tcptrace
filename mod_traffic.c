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
static char const rcsid_traffic[] =
   "$Id$";

#ifdef LOAD_MODULE_TRAFFIC

#include "tcptrace.h"
#include "mod_traffic.h"


/* info kept for each (active) port */
struct traffic_info {
    /* which port */
    u_short port;
    
    /* interval byte counters */
    u_long nbytes;
    u_long last_nbytes;
    u_long ttlbytes;

    /* interval packet counters */
    u_long npackets;
    u_long last_npackets;
    u_long ttlpackets;

    /* active connections */
    u_long nactive;
    u_long last_nactive;
    u_long ttlactive;

    /* which color is used for plotting */
    char *color;

    /* did we draw the label yet? */
    Bool labelled;

    /* linked list of the one's we're using */
    struct traffic_info *next;
};
static struct traffic_info *traffichead = NULL;
#define NUM_PORTS 65536
static struct traffic_info *ports[NUM_PORTS] = {NULL,NULL /* ... */ };
#define EXCLUDE_PORT ((void *)(-1))
#define INCLUDE_PORT (NULL)

/* additional info kept per connection */
struct conn_info {
    Bool wasactive;		/* was this connection active over the interval? */
    struct traffic_info *pti1;	/* pointer to the port info for this one */
    struct traffic_info *pti2;	/* pointer to the port info for this one */
    struct conn_info *next;	/* next in the chain */
};
static struct conn_info *connhead = NULL;



/* plotter files we keep open */
static PLOTTER plotter_bytes;
static PLOTTER plotter_packets;
static PLOTTER plotter_active;



/* local routines */
static struct traffic_info *MakeTrafficRec(u_short port);
static struct conn_info *MakeConnRec(void);
static void AgeTraffic(void);
static struct traffic_info *FindPort(u_short port);
static void IncludePorts(unsigned firstport, unsigned lastport);
static void ExcludePorts(unsigned firstport, unsigned lastport);
static void CheckPortNum(unsigned portnum);
static char *PortName(int port);

/* other globals */
float age_interval = 15.0;  /* 15 seconds by default */


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
    char *pch;
    char *portspec = NULL;
    static int excluded = 0;

    for (i=1; i < argc; ++i) {
	if (!argv[i])
	    continue;  /* argument already taken by another module... */
	if (strncmp(argv[i],"-x",2) == 0) {
	    if (strncasecmp(argv[i]+2,"traffic",sizeof("traffic")-1) == 0) {
		/* I want to be called */
		portspec = argv[i]+(sizeof("-xtraffic")-1);
		enable = 1;
		printf("mod_traffic: characterizing all traffic\n");
		argv[i] = NULL;
	    }
	}
    }

    if (!enable)
	return(0);	/* don't call me again */

    /* check for ports specification */
    if (portspec && *portspec) {

	/* search the port specs */
	pch = portspec;
	while (pch && *pch) {
	    char *pch_next;
	    float interval;
	    unsigned port1, port2;

	    if ((pch_next = strchr(pch,',')) != NULL) {
		*pch_next = '\00';
		++pch_next;
	    }

	    if (sscanf(pch,"=%f", &interval) == 1) {
		age_interval = interval;
		if (debug)
		    printf("mod_traffic: setting age interval to %.3f seconds\n",
			   age_interval);
	    } else {
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
	    }

	    pch = pch_next;
	}
    }

    

    ports[0] = MakeTrafficRec(0);

    /* open the output files */
    plotter_packets =
	new_plotter(NULL,
		    "traffic_packets.xpl",
		    "packets per second over time by port",
		    "time","packets/second",
		    NULL);
    plotter_bytes =
	new_plotter(NULL,
		    "traffic_bytes.xpl",
		    "bytes per second over time by port",
		    "time","bytes/second",
		    NULL);
    plotter_active =
	new_plotter(NULL,
		    "traffic_conns.xpl",
		    "active connections over time by port",
		    "time","active connections",
		    NULL);

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
    if (pti == EXCLUDE_PORT)
	return(NULL);

    /* make a new one if there's a NULL there */
    if (!pti) {
	pti = MakeTrafficRec(port);
    }

    return(pti);
}





static struct traffic_info *
MakeTrafficRec(
    u_short port)
{
    struct traffic_info *pti;
    static int nextcolor = 0;

    pti = MallocZ(sizeof(struct traffic_info));

    /* init */
    pti->port = port;

    /* pick color */
    pti->color = ColorNames[nextcolor % NCOLORS];
    ++nextcolor;

    /* chain it in (at head of list) */
    pti->next = traffichead;
    traffichead = pti;

    /* add to lookup array */
    ports[port] = pti;

    return(pti);
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

    /* determine elapsed time and age the samples (every 15 seconds now) */
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

    /* roll the active connections into the port records */
    for (pci=connhead; pci; pci=pci->next) {
	if (pci->wasactive) {
	    if (pci->pti1)
		++pci->pti1->nactive;
	    if (pci->pti2)
		++pci->pti2->nactive;
	    pci->wasactive = 0;
	    ++ports[0]->nactive;
	}
    }
    

    /* print them out */
    for (pti=traffichead; pti; pti=pti->next) {
	if (debug>1)
	    printf("  Aging Port %u   bytes: %lu  packets: %lu\n",
		   pti->port, pti->nbytes, pti->npackets);

	/* plot bytes */
	ups = (int)((float)pti->nbytes * 1000000.0 / etime);
	plotter_perm_color(plotter_bytes, pti->color);
	if (!pti->labelled || ((ups > 0) && (pti->last_nbytes == 0)))
	    plotter_text(plotter_bytes, current_time, ups,
			 "l", PortName(pti->port));
	plotter_dot(plotter_bytes, current_time, ups);
	if (last_time.tv_sec)
	    plotter_line(plotter_bytes,
			 current_time, ups, last_time, pti->last_nbytes);
	pti->last_nbytes = ups;

	/* plot packets */
	ups = (int)((float)pti->npackets * 1000000.0 / etime);
	plotter_perm_color(plotter_packets, pti->color);
	if (!pti->labelled || ((ups > 0) && (pti->last_npackets == 0)))
	    plotter_text(plotter_packets, current_time, ups,
			 "l", PortName(pti->port));
	plotter_dot(plotter_packets, current_time, ups);
	if (last_time.tv_sec)
	    plotter_line(plotter_packets,
			 current_time, ups, last_time, pti->last_npackets);
	pti->last_npackets = ups;

	/* plot active connections */
	plotter_perm_color(plotter_active, pti->color);
	if (!pti->labelled || ((pti->nactive > 0) && (pti->last_nactive == 0)))
	    plotter_text(plotter_active, current_time, pti->nactive,
			 "l", PortName(pti->port));
	plotter_dot(plotter_active, current_time, pti->nactive);
	if (last_time.tv_sec)
	    plotter_line(plotter_active,
			 current_time, pti->nactive, last_time, pti->last_nactive);
	pti->last_nactive = pti->nactive;

	/* OK, we must have done the left hand label by now */
	pti->labelled = 1;
    }


    /* zero them out */
    for (pti=traffichead; pti; pti=pti->next) {
	pti->ttlbytes += pti->nbytes;
	pti->ttlpackets += pti->npackets;

	pti->nbytes = 0;
	pti->npackets = 0;
	pti->nactive = 0;
    }

    last_time = current_time;
}


void	
traffic_done(void)
{
    struct traffic_info *pti;
    struct conn_info *pci;
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

    /* print them out */
    printf("Overall totals by port\n");
    for (i=0; i < NUM_PORTS; ++i) {
	pti = ports[i];
	if ((pti != EXCLUDE_PORT) && (pti != INCLUDE_PORT)) {
	    if (i == 0)
		printf("Port TTL ");
	    else
		printf("Port %5u   ", pti->port);
	    printf("bytes: %12lu  packets: %10lu  connections: %8lu\n",
		   pti->ttlbytes, pti->ttlpackets, pti->ttlactive);
	}
    }

    printf("Plotting performed at %.3f second intervals\n", age_interval);
}


void
traffic_usage(void)
{
    printf("\t-xtraffic[PORTSPEC]\tprint info about overall traffic\n");
    printf("\
\t   PORTSPEC format:\n\
\t       =S         set statistics interval to S (float) seconds, default 15.0\n\
\t       P          include information on port P\n\
\t       P1-P2      include information on ports in the range [P1-P2]\n\
\t       -P         exclude information on port P\n\
\t       -P1-P2     exclude information on ports in the range [P1-P2]\n\
\t       SPEC,SPEC  commas chain together specs\n\
\t     Examples\n\
\t       -xtraffic23            only port 23\n\
\t       -xtraffic1-1023        only ports 1-1023\n\
\t       -xtraffic1-1023,-10-20 only ports 1-1023, but exclude ports 10-20\n\
\t     With no ports specification, all ports are gathered.  With ANY\n\
\t     spec, all ports are initially EXCLUDED\n\
");
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
#endif /* LOAD_MODULE_TRAFFIC */
