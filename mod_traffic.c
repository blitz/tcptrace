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

    /* open connections */
    u_long nopen;
    u_long last_nopen;
    u_long ttlopen;

    /* which color is used for plotting */
    char *color;

    /* did we draw the label yet? */
    Bool labelled;

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
    struct traffic_info *pti1;	/* pointer to the port info for this one */
    struct traffic_info *pti2;	/* pointer to the port info for this one */
    struct conn_info *next;	/* next in the chain */

    u_int last_dupacks;		/* last value of dupacks I saw */
    u_int last_rexmits;		/* last value of rexmits I saw */
};
static struct conn_info *connhead = NULL;



/* plotter files that we keep open */
static PLOTTER plotter_bytes;
static PLOTTER plotter_packets;
static PLOTTER plotter_active;
static PLOTTER plotter_open;
static PLOTTER plotter_openclose;
static PLOTTER plotter_loss;

#define  PLOTTER_BYTES_FILENAME		"traffic_bytes.xpl"
#define  PLOTTER_PACKETS_FILENAME	"traffic_packets.xpl"
#define  PLOTTER_ACTIVE_FILENAME	"traffic_active.xpl"
#define  PLOTTER_OPEN_FILENAME		"traffic_open.xpl"
#define  PLOTTER_OPENCLOSE_FILENAME	"traffic_openclose.xpl"
#define  PLOTTER_LOSS_FILENAME		"traffic_loss.xpl"

/* argument flags */
static float age_interval = 15.0;  /* 15 seconds by default */
static Bool doplot_bytes = FALSE;
static Bool doplot_packets = FALSE;
static Bool doplot_active = FALSE;
static Bool doplot_open = FALSE;
static Bool doplot_openclose = FALSE;
static Bool doplot_loss = FALSE;



/* local routines */
static struct traffic_info *MakeTrafficRec(u_short port);
static struct conn_info *MakeConnRec(void);
static void AgeTraffic(void);
static struct traffic_info *FindPort(u_short port);
static void IncludePorts(unsigned firstport, unsigned lastport);
static void ExcludePorts(unsigned firstport, unsigned lastport);
static void CheckPortNum(unsigned portnum);
static char *PortName(int port);
static void ParseArgs(char *argstring);

/* for other stats on connections */
static int last_num_closes = 0;
static int last_num_opens = 0;
static int last_open_conns = 0;
static int num_closes = 0;
static int num_opens = 0;
static int open_conns = 0;

/* counters for loss events */
static int dupacks;
static int last_dupacks;
static int rexmits;
static int last_rexmits;

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
    if (doplot_open)
	plotter_open =
	    new_plotter(NULL,
			PLOTTER_OPEN_FILENAME,
			"open connections over time by port",
			"time","open connections",
			NULL);
    if (doplot_openclose)
	plotter_openclose =
	    new_plotter(NULL,
			PLOTTER_OPENCLOSE_FILENAME,
			"connections opened and closed over time",
			"time","number of connections",
			NULL);
    if (doplot_loss)
	plotter_loss =
	    new_plotter(NULL,
			PLOTTER_LOSS_FILENAME,
			"packet loss per second over time",
			"time","events/second",
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

    /* check to see if it's really "open" (traffic in both directions) */
    if (!pci->wasopen) {
	if ((ptp->a2b.packets > 0) && (ptp->b2a.packets > 0)) {
	    /* bidirectional: OK, we'll call it open */
	    pci->wasopen = 1;
	    pci->isopen = 1;
	    ++num_opens;
	    ++open_conns;
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

    /* see if we're closing it */
    if (FIN_SET(ptcp) || RESET_SET(ptcp)) {
	if (pci->isopen) {
	    pci->isopen = 0;
	    ++num_closes;
	    --open_conns;
	}
    }

    /* check losses */
    if (pci->last_dupacks != ptp->a2b.rtt_dupack+ptp->b2a.rtt_dupack) {
	pci->last_dupacks = ptp->a2b.rtt_dupack+ptp->b2a.rtt_dupack;
	++dupacks;
    }
    if (pci->last_rexmits != ptp->a2b.rexmit_pkts+ptp->b2a.rexmit_pkts) {
	pci->last_rexmits = ptp->a2b.rexmit_pkts+ptp->b2a.rexmit_pkts;
	++rexmits;
    }


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

    /* roll the open/active connections into the port records */
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
	}
    }
    

    /* ============================================================ */
    /* plot connection activity */
    /* opens */
    if (doplot_openclose) {
	static Bool openclose_labelled = 0;
	plotter_perm_color(plotter_openclose, "green");
	plotter_dot(plotter_openclose, current_time, num_opens);
	if (!ZERO_TIME(&last_time))
	    plotter_line(plotter_openclose,
			 current_time, num_opens,
			 last_time, last_num_opens);
	last_num_opens = num_opens;
	num_opens = 0;


	/* closes */
	plotter_perm_color(plotter_openclose, "red");
	plotter_dot(plotter_openclose, current_time, num_closes);
	if (!ZERO_TIME(&last_time))
	    plotter_line(plotter_openclose,
			 current_time, num_closes,
			 last_time, last_num_closes);
	
	last_num_closes = num_closes;
	num_closes = 0;

	/* total open */
	pti = FindPort(0);
	plotter_perm_color(plotter_openclose, "blue");
	plotter_dot(plotter_openclose, current_time, open_conns);
	if (!ZERO_TIME(&last_time))
	    plotter_line(plotter_openclose,
			 current_time, open_conns,
			 last_time, last_open_conns);
	last_open_conns = open_conns;

	/* insert labels */
	if (!openclose_labelled) {
	    if (!ZERO_TIME(&last_time)) {
		plotter_temp_color(plotter_openclose, "green");
		plotter_text(plotter_openclose, current_time, last_num_opens,
			     "l", "Number Opens");
		plotter_temp_color(plotter_openclose, "red");
		plotter_text(plotter_openclose, current_time, last_num_closes,
			     "l", "Number Closes");
		plotter_temp_color(plotter_openclose, "blue");
		plotter_text(plotter_openclose, current_time, open_conns,
			     "l", "Total Open");
	    }
	    openclose_labelled = 1;
	}
    }


    /* ============================================================ */
    /* report of loss events */
    if (doplot_loss) {
	static Bool loss_labelled = 0;

	dupacks = (int)((float)dupacks/age_interval);/* convert to events/second */
	plotter_perm_color(plotter_loss, "yellow");
	plotter_dot(plotter_loss, current_time, dupacks);
	if (!ZERO_TIME(&last_time))
	    plotter_line(plotter_loss,
			 current_time, dupacks,
			 last_time, last_dupacks);
	last_dupacks = dupacks;
	dupacks = 0;

	rexmits = (int)((float)rexmits/age_interval);/* convert to events/second */
	plotter_perm_color(plotter_loss, "blue");
	plotter_dot(plotter_loss, current_time, rexmits);
	if (!ZERO_TIME(&last_time))
	    plotter_line(plotter_loss,
			 current_time, rexmits,
			 last_time, last_rexmits);
	last_rexmits = rexmits;
	rexmits = 0;
	/* insert labels */
	if (!loss_labelled) {
	    if (!ZERO_TIME(&last_time)) {
		plotter_temp_color(plotter_loss, "yellow");
		plotter_text(plotter_loss, current_time, last_dupacks,
			     "l", "Number Dupacks");
		plotter_temp_color(plotter_loss, "blue");
		plotter_text(plotter_loss, current_time, last_rexmits,
			     "l", "Number Retransmits");
	    }
	    loss_labelled = 1;
	}
    }


    /* ============================================================ */
    /* print them out */
    for (pti=traffichead; pti; pti=pti->next) {
	if (debug>1)
	    printf("  Aging Port %u   bytes: %lu  packets: %lu\n",
		   pti->port, pti->nbytes, pti->npackets);

	/* plot bytes */
	if (doplot_bytes) {

	    ups = (int)((float)pti->nbytes * 1000000.0 / etime);
	    plotter_perm_color(plotter_bytes, pti->color);
	    if (!pti->labelled || ((ups > 0) && (pti->last_nbytes == 0)))
		plotter_text(plotter_bytes, current_time, ups,
			     "l", PortName(pti->port));
	    plotter_dot(plotter_bytes, current_time, ups);
	    if (!ZERO_TIME(&last_time))
		plotter_line(plotter_bytes,
			     current_time, ups, last_time, pti->last_nbytes);
	    pti->last_nbytes = ups;
	}

	/* plot packets */
	if (doplot_packets) {
	    ups = (int)((float)pti->npackets * 1000000.0 / etime);
	    plotter_perm_color(plotter_packets, pti->color);
	    if (!pti->labelled || ((ups > 0) && (pti->last_npackets == 0)))
		plotter_text(plotter_packets, current_time, ups,
			     "l", PortName(pti->port));
	    plotter_dot(plotter_packets, current_time, ups);
	    if (!ZERO_TIME(&last_time))
		plotter_line(plotter_packets,
			     current_time, ups, last_time, pti->last_npackets);
	    pti->last_npackets = ups;
	}

	/* plot active connections */
	if (doplot_active) {
	    plotter_perm_color(plotter_active, pti->color);
	    if (!pti->labelled || ((pti->nactive > 0) && (pti->last_nactive == 0)))
		plotter_text(plotter_active, current_time, pti->nactive,
			     "l", PortName(pti->port));
	    plotter_dot(plotter_active, current_time, pti->nactive);
	    if (!ZERO_TIME(&last_time))
		plotter_line(plotter_active,
			     current_time, pti->nactive, last_time, pti->last_nactive);
	    pti->last_nactive = pti->nactive;
	}

	/* plot open connections */
	if (doplot_open) {
	    plotter_perm_color(plotter_open, pti->color);
	    if (!pti->labelled || ((pti->nopen > 0) && (pti->last_nopen == 0)))
		plotter_text(plotter_open, current_time, pti->nopen,
			     "l", PortName(pti->port));
	    plotter_dot(plotter_open, current_time, pti->nopen);
	    if (!ZERO_TIME(&last_time))
		plotter_line(plotter_open,
			     current_time, pti->nopen, last_time, pti->last_nopen);
	    pti->last_nopen = pti->nopen;
	}

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
	pti->nopen = 0;
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
\t       -L           generate the 'losses per second' graph\n\
\t       -O           generate the 'open connections' graph\n\
\t       -C           generate the 'opens and closes' graph\n\
\t       -P           generate the 'packets per second' graph\n\
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
	    debug = 1;
	} else if (sscanf(argv[i],"-i%f", &interval) == 1) {
	    age_interval = interval;
	    if (debug)
		printf("mod_traffic: setting age interval to %.3f seconds\n",
		       age_interval);
	} else if (strcmp(argv[i],"-G") == 0) {
	    doplot_active = TRUE;
	    doplot_bytes = TRUE;
	    doplot_loss = TRUE;
	    doplot_open = TRUE;
	    doplot_openclose = TRUE;
	    doplot_packets = TRUE;
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
	} else if (strcmp(argv[i],"-L") == 0) {
	    doplot_loss = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'loss' graph into '%s'\n",
			PLOTTER_LOSS_FILENAME);
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
	} else if (strcmp(argv[i],"-P") == 0) {
	    doplot_packets = TRUE;
	    if (debug)
		fprintf(stderr,
			"mod_traffic: generating 'packets' graph into '%s'\n",
			PLOTTER_PACKETS_FILENAME);
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

#endif /* LOAD_MODULE_TRAFFIC */
