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
 * Original Author: Eric Helvey
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ehelvey@cs.ohiou.edu
 * Extensively Modified:    Shawn Ostermann
 */
static char const rcsid[] =
   "$Header$";

#ifdef LOAD_MODULE_TCPLIB

/****************************************************************************
 * 
 * Module Title: Mod_TCPLib 
 * 
 * Author: Eric Helvey
 * 
 * Purpose: To generate data files needed by TCPLib and TrafGen.
 * 
 ****************************************************************************/
#include "tcptrace.h"
#include "mod_tcplib.h"
#include "dyncounter.h"


/* Local global variables */

/* different types of connections */
#define NUM_TCB_TYPES 4
enum t_statsix {LOCAL = 0, INCOMING = 1, OUTGOING = 2, REMOTE = 3};
static char *ttype_names[NUM_TCB_TYPES] = {"local","incoming","outgoing", "remote"};

/* structure to keep track of "inside" */
struct insidenode {
    ipaddr min;
    ipaddr max;
    struct insidenode *next;
} *inside_head = NULL;
#define LOCAL_ONLY (inside_head == NULL)



/* for VM efficiency, we pull the info that we want out of the tcptrace
   structures into THIS structure (or large files thrash) */
typedef struct module_conninfo_tcb {
    /* cached connection type (incoming, remote, etc) */
    enum t_statsix ttype;

    /* cached data bytes */
    u_llong	data_bytes;

    /* if it's FTP CONTROL, HTTP, or NNTP, we track numitems */
    u_long numitems;

    /* last time new data was sent */
    timeval	last_data_time;

    /* link back to REAL information */
    tcb 	*ptcb;

    /* previous connection of same type */
    struct module_conninfo *prev_ttype;
} module_conninfo_tcb;


/* structure that this module keeps for each connection */
typedef struct module_conninfo {
    /* cached info */
    struct module_conninfo_tcb tcb_cache_a2b;
    struct module_conninfo_tcb tcb_cache_b2a;

    /* breakdown type */
    short btype;

    /* cached copy of address pair */
    tcp_pair_addrblock	addr_pair;

    /* link back to the tcb's */
    tcp_pair *ptp;

    /* time of connection start */
    timeval	first_time;
    timeval	last_time;

    /* previous connection in linked list of all connections */
    struct module_conninfo *prev;

    /* for determining bursts */
    tcb *tcb_lastdata;

    /* next connection in linked list by endpoint pairs */
    struct module_conninfo *next_pair;
} module_conninfo;
module_conninfo *module_conninfo_tail = NULL;


/* data structure to store endpoint pairs */
typedef struct endpoint_pair {
    /* endpoint identification */
    tcp_pair_addrblock	addr_pair;

    /* linked list of connections using that pair */
    module_conninfo *pmchead;

    /* next address pair */
    struct endpoint_pair *pepnext;
} endpoint_pair;
#define ENDPOINT_PAIR_HASHSIZE 1023



static struct tcplibstats {
    /* telnet packet sizes */
    dyn_counter telnet_pktsize;

    /* telnet interarrival times */
    dyn_counter telnet_interarrival;

    /* conversation interarrival times */
    dyn_counter conv_interarrival;

    /* conversation duration */
    dyn_counter conv_duration;

    /* for the interval breakdowns */
    int interval_count;
    timeval last_interval;
    int tcplib_breakdown_interval[NUM_APPS];

    /* histogram files */
    FILE *hist_file;

    /* For HTTP, we track idle time between bursts */
    dyn_counter http_idletime;

    /* telnet packet sizes */
    dyn_counter throughput;
    int throughput_bytes;
} *global_pstats[NUM_TCB_TYPES] = {NULL};


/* local debugging flag */
static int ldebug = 0;

/* offset for all ports */
static int ipport_offset = 0;

/* the name of the directory (prefix) for the output */
static char *output_dir = DEFAULT_TCPLIB_DATADIR;

/* the name of the current tcptrace input file */
static char *current_file = NULL;

/* characters to print in interval breakdown file */
static const char breakdown_hash_char[] = { 'S', 'N', 'T', 'F', 'H', 'f'};


/* FTP endpoints hash table */
endpoint_pair *ftp_endpoints[ENDPOINT_PAIR_HASHSIZE];


/* internal types */
typedef Bool (*f_testinside) (module_conninfo *pmc,
			      module_conninfo_tcb *ptcbc);

/* various statistics and counters */
static u_long newconn_counter;	/* total conns */
static u_long newconn_badport;	/* a port we don't want */
static u_long newconn_goodport;	/* we want the port */
static u_long newconn_ftp_data_heuristic; /* merely ASSUMED to be ftp data */
/* conns by type */
static u_long conntype_counter[NUM_TCB_TYPES];
/* both flows have data */
static u_long conntype_duplex_counter[NUM_TCB_TYPES];
/* this flow has data, twin is empty */
static u_long conntype_uni_counter[NUM_TCB_TYPES];
/* this flow has NO data, twin is NOT empty */
static u_long conntype_nodata_counter[NUM_TCB_TYPES];
/* neither this flow OR its twin has data */
static u_long conntype_noplex_counter[NUM_TCB_TYPES];



/* Function Prototypes */
static void ParseArgs(char *argstring);
static int breakdown_type(tcp_pair *ptp);
static void do_final_breakdown(char* filename, f_testinside p_tester,
			       struct tcplibstats *pstats);
static void do_all_final_breakdowns(void);
static void do_all_conv_arrivals(void);
static void do_tcplib_final_converse(char *filename,
				     dyn_counter psizes);
static void do_tcplib_next_converse(module_conninfo_tcb *ptcbc,
				    module_conninfo *pmc);
static void do_tcplib_conv_duration(char *filename,
				    dyn_counter psizes);
static void do_tcplib_next_duration(module_conninfo_tcb *ptcbc,
				    module_conninfo *pmc);

/* prototypes for connection-type determination */
static Bool is_ftp_ctrl_port(portnum port);
static Bool is_ftp_data_port(portnum port);
static Bool is_http_port(portnum port);
static Bool is_nntp_port(portnum port);
static Bool is_smtp_port(portnum port);
static Bool is_telnet_port(portnum port);

/* shorthand */
#define is_ftp_ctrl_conn(pmc)	(pmc->btype == TCPLIBPORT_FTPCTRL)
#define is_ftp_data_conn(pmc)	(pmc->btype == TCPLIBPORT_FTPDATA)
#define is_http_conn(pmc)	(pmc->btype == TCPLIBPORT_HTTP)
#define is_nntp_conn(pmc)	(pmc->btype == TCPLIBPORT_NNTP)
#define is_smtp_conn(pmc)	(pmc->btype == TCPLIBPORT_SMTP)
#define is_telnet_conn(pmc)	(pmc->btype == TCPLIBPORT_TELNET)


static char* namedfile(char *localsuffix, char * file);
static void setup_breakdown(void);
static void tcplib_add_telnet_interarrival(tcp_pair *ptp,
					   module_conninfo *pmc,
					   dyn_counter *psizes);
static void tcplib_add_telnet_packetsize(struct tcplibstats *pstats,
					 int length);
static void tcplib_do_ftp_control_size(char *filename, f_testinside p_tester);
static void tcplib_do_ftp_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_ftp_numitems(char *filename, f_testinside p_tester);
static void tcplib_do_http_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_nntp_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_nntp_numitems(char *filename, f_testinside p_tester);
static void tcplib_do_smtp_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_telnet_duration(char *filename, f_testinside p_tester);
static void tcplib_do_telnet_interarrival(char *filename,
					  f_testinside p_tester);
static void tcplib_do_telnet_packetsize(char *filename,
					f_testinside p_tester);
static void tcplib_init_setup(void);
static void update_breakdown(tcp_pair *ptp, struct tcplibstats *pstats);
module_conninfo *FindPrevConnection(module_conninfo *pmc,
					   enum t_statsix ttype);
static char *FormatBrief(tcp_pair *ptp);
static char *FormatAddrBrief(tcp_pair_addrblock *addr_pair);
static void ModuleConnFillcache(void);


/* prototypes for determining "insideness" */
static void DefineInside(char *iplist);
static Bool IsInside(ipaddr *pipaddr);

static Bool TestOutgoing(module_conninfo*, module_conninfo_tcb *ptcbc);
static Bool TestIncoming(module_conninfo*, module_conninfo_tcb *ptcbc);
static Bool TestLocal(module_conninfo*, module_conninfo_tcb *ptcbc);
static Bool TestRemote(module_conninfo*, module_conninfo_tcb *ptcbc);

static int InsideBytes(module_conninfo*, f_testinside);
static enum t_statsix traffic_type(module_conninfo *pmc,
				   module_conninfo_tcb *ptcbc);

/* prototypes for endpoint pairs */
static void TrackEndpoints(module_conninfo *pmc);
static hash EndpointHash(tcp_pair_addrblock *addr_pair);
static hash IPHash(ipaddr *paddr);
static Bool SameEndpoints(tcp_pair_addrblock *paddr_pair1,
			  tcp_pair_addrblock *paddr_pair2);
static struct module_conninfo_tcb *MostRecentFtpControl(endpoint_pair *pep);
static Bool CouldBeFtpData(tcp_pair *ptp);
static void AddEndpointPair(endpoint_pair *hashtable[],
			    module_conninfo *pmc);
static endpoint_pair *FindEndpointPair(endpoint_pair *hashtable[],
				       tcp_pair_addrblock *paddr_pair);
static Bool IsNewBurst(module_conninfo *pmc, tcb *ptcb, seqnum seq);


/* various helper routines used by many others -- sdo */
static Bool ActiveConn(module_conninfo *pmc);
static void tcplib_do_GENERIC_itemsize(
    char *filename, int btype,
    f_testinside p_tester, int bucketsize);
static void tcplib_do_GENERIC_numitems(
    char *filename, int btype,
    f_testinside p_tester);
static void StoreCounters(char *filename, char *header1, char *header2,
		       int bucketsize, dyn_counter psizes);
static dyn_counter ReadOldFile(char *filename, int bucketsize,
				 int maxlegal, dyn_counter psizes);



/* First section is comprised of functions that TCPTrace will call
 * for all modules.
 */

/***************************************************************************
 * 
 * Function Name: tcplib_init
 * 
 * Returns:  TRUE/FALSE whether or not the tcplib module for tcptrace
 *           has been requested on the command line.
 *
 * Purpose: To parse the command line arguments for the tcplib module's
 *          command line flags, return whether or not to run the module,
 *          and to set up the local global variables needed to generate
 *          the tcplib data files.
 *
 * Called by: LoadModules() in tcptrace.c
 * 
 * 
 ****************************************************************************/
int tcplib_init(
    int argc,      /* Number of command line arguments */
    char *argv[]   /* Command line arguments */
    )
{
    int i;             /* Runner for command line arguments */
    int enable = 0;    /* Do we turn on this module, or not? */
    char *args = NULL;

    for(i = 0; i < argc; i++) {
	if (!argv[i])
	    continue;

	/* See if they want to use us */
	if ((argv[i] != NULL) && (strncmp(argv[i], "-xtcplib", 8) == 0)) {
	    /* Calling the Tcplib part */
	    enable = 1;
	    args = argv[i]+(sizeof("-xtcplib")-1);

	    printf("Capturing TCPLib traffic\n");

	    /* We free this argument so that no other modules
	     * or the main program mis-interprets this flag.
	     */
	    argv[i] = NULL;

	    continue;
	}
    }

    /* If enable is not true, then all tcplib functions will
     * be ignored during this run of the program.
     */
    if (!enable)
	return(0);	/* don't call me again */

    /* parse the encoded args */
    ParseArgs(args);

    /* init internal data */
    tcplib_init_setup();

    /* don't care for detailed output! */
    printsuppress = TRUE; 

    return TRUE;
}


/* wants strings of the form IP1-IP2 */
static struct insidenode *
DefineInsideRange(
    char *ip_pair)
{
    char *pdash;
    struct insidenode *pnode;
    ipaddr *paddr;

    if (ldebug>2)
	printf("DefineInsideRange('%s') called\n", ip_pair);

    pdash = strchr(ip_pair,'-');
    if (pdash == NULL) {
	return(NULL);
    }

    *pdash = '\00';

    pnode = MallocZ(sizeof(struct insidenode));

    paddr = str2ipaddr(ip_pair);
    if (paddr == NULL) {
	fprintf(stderr,"invalid IP address: '%s'\n", ip_pair);
	exit(-1);
    }
    pnode->min = *paddr;


    paddr = str2ipaddr(pdash+1);
    if (paddr == NULL) {
	fprintf(stderr,"invalid IP address: '%s'\n", pdash+1);
	exit(-1);
    }
    pnode->max = *paddr;

    return(pnode);
}


static struct insidenode *
DefineInsideRecurse(
    char *iplist)
{
    char *pcomma;
    struct insidenode *left;

    /* find commas and recurse */
    pcomma = strchr(iplist,',');

    if (pcomma) {
	*pcomma = '\00';
	left = DefineInsideRecurse(iplist);
	left->next = DefineInsideRecurse(pcomma+1);

	return(left);
    } else {
	/* just one term left */
	return(DefineInsideRange(iplist));
    }
}



static void
DefineInside(
    char *iplist)
{
    
    if (ldebug>2)
	printf("DefineInside(%s) called\n", iplist);

    inside_head = DefineInsideRecurse(iplist);

    if (ldebug) {
	struct insidenode *phead;
	printf("DefineInside: result:\n  ");
	for (phead=inside_head; phead; phead=phead->next) {
	    printf("(%s <= addr", HostAddr(phead->min));
	    printf(" <= %s)", HostAddr(phead->max));
	    if (phead->next)
		printf(" OR ");
	}
	printf("\n");
    }
}


static Bool
IsInside(
    ipaddr *paddr)
{
    struct insidenode *phead;

    /* if use didn't specify "inside", then EVERYTHING is "inside" */
    if (LOCAL_ONLY)
	return(TRUE);

    for (phead = inside_head; phead; phead=phead->next) {
	int cmp1 = IPcmp(&phead->min, paddr);
	int cmp2 = IPcmp(&phead->max, paddr);

	if ((cmp1 == -2) || (cmp2 == -2)) {
	    /* not all the same address type, fail */
	    return(FALSE);
	}

	if ((cmp1 <= 0) &&	/* min <= addr */
	    (cmp2 >= 0))	/* max >= addr */
	    return(TRUE);
    }
    return(FALSE);
}

static Bool
TestOutgoing(
    module_conninfo *pmc,
    module_conninfo_tcb *ptcbc)
{
    if (ptcbc == &pmc->tcb_cache_a2b)
	return( IsInside(&pmc->addr_pair.a_address) &&
	       !IsInside(&pmc->addr_pair.b_address));
    else
	return( IsInside(&pmc->addr_pair.b_address) &&
	       !IsInside(&pmc->addr_pair.a_address));
}

static Bool
TestIncoming(
    module_conninfo *pmc,
    module_conninfo_tcb *ptcbc)
{
    if (ptcbc == &pmc->tcb_cache_a2b)
	return(!IsInside(&pmc->addr_pair.a_address) &&
	        IsInside(&pmc->addr_pair.b_address));
    else
	return(!IsInside(&pmc->addr_pair.b_address) &&
	        IsInside(&pmc->addr_pair.a_address));
}


static Bool
TestLocal(
    module_conninfo *pmc,
    module_conninfo_tcb *ptcbc)
{
    return(IsInside(&pmc->addr_pair.a_address) &&
	   IsInside(&pmc->addr_pair.b_address));
}


static Bool
TestRemote(
    module_conninfo *pmc,
    module_conninfo_tcb *ptcbc)
{
    return(!IsInside(&pmc->addr_pair.a_address) &&
	   !IsInside(&pmc->addr_pair.b_address));
}


static int InsideBytes(
    module_conninfo *pmc,
    f_testinside p_tester)	/* function to test "insideness" */
{
    int temp = 0;

    /* if "p_tester" likes this side of the connection, count the bytes */
    if ((*p_tester)(pmc, &pmc->tcb_cache_a2b))
	temp += pmc->tcb_cache_a2b.data_bytes;

    /* if "p_tester" likes this side of the connection, count the bytes */
    if ((*p_tester)(pmc, &pmc->tcb_cache_b2a))
	temp += pmc->tcb_cache_b2a.data_bytes;

    return(temp);
}


static void
ParseArgs(char *argstring)
{
    int argc;
    char **argv;
    int i;
    
    /* make sure there ARE arguments */
    if (!(argstring && *argstring))
	return;

    /* break the string into normal arguments */
    StringToArgv(argstring,&argc,&argv);

    /* check the module args */
    for (i=1; i < argc; ++i) {
	/* The "-o####" flag sets the offset that we're going
	 * to consider for tcplib data files.  The reason is that
	 * for verification purposes, when trafgen creates traffic 
	 * it sends it to non-standard ports.  So, in order to get
	 * a data set from generated traffic, we'd have to remove
	 * the offset.  The -o allows us to do that.
	 */
	if (argv[i] && !strncmp(argv[i], "-o", 2)) {
	    ipport_offset = atoi(argv[i]+2);

	    if (!ipport_offset) {
		fprintf(stderr, "\
Invalid argument to flag \"-o\".\n\
Must be integer value greater than 0.\n");
		exit(1);
	    }

	    printf("TCPLib port offset - %d\n", ipport_offset);
	}


	/* The "-iIPs" gives the definition of "inside".  When it's used,
	 * we divide the the data into four sets:
	 * data.incoming:
	 *    for all data flowing from "inside" to "outside"
	 * data.outgoing:
	 *    for all data flowing from "outside" to "inside"
	 * data.local:
	 *    for all data flowing from "inside" to "inside"
	 * data.remote:
	 *    for all data flowing from "outside" to "outside"
	 *        (probably an error)
	 */
	else
	if (argv[i] && !strncmp(argv[i], "-i", 2)) {
	    if (!isdigit((int)*(argv[i]+2))) {
		fprintf(stderr,"-i requires IP address list\n");
		tcplib_usage();
		exit(-1);
	    }
		
	    DefineInside(argv[i]+2);
	}


	/* local debugging flag */
	else
	if (argv[i] && !strncmp(argv[i], "-d", 2)) {
	    ++ldebug;
	}



	/* We will probably need to add another flag here to
	 * specify the directory in which to place the data
	 * files.  And here it is.
	 */
	else if (argv[i] && !strncmp(argv[i], "-D", 2)) {
	    char *pdir = argv[i]+2;

	    if (!pdir) {
		fprintf(stderr,"argument -DDIR requires directory name\n");
		exit(-1);
	    }

	    output_dir = strdup(pdir);

	    printf("TCPLib output directory - %sdata\n", output_dir);
	}

	/*  ... else invalid */
	else {
	    fprintf(stderr,"tcplib module: bad argument '%s'\n",
		    argv[i]);
	    exit(-1);
	}
    }

}




/***************************************************************************
 * 
 * Function Name: tcplib_done
 * 
 * Returns: Nothing
 *
 * Purpose: This function runs after all the packets have been read in
 *          and filed.  The functions that tcplib_done calls are the ones
 *          that generate the data files.
 *
 * Called by: FinishModules() in tcptrace.c
 * 
 * 
 ****************************************************************************/
static void
RunAllFour(
    void (*f_runme) (char *,f_testinside),
    char *thefile)
{
    char *filename;

    filename = namedfile("local",thefile);
    (*f_runme)(filename,TestLocal);

    if (LOCAL_ONLY)
	return;  /* none of the rest will match anyway */

    filename = namedfile("incoming",thefile);
    (*f_runme)(filename,TestIncoming);

    filename = namedfile("outgoing",thefile);
    (*f_runme)(filename,TestOutgoing);

    filename = namedfile("remote",thefile);
    (*f_runme)(filename,TestRemote);

}
void tcplib_done()
{
    char *filename;
    int i;

    /* fill the info cache */
    if (ldebug)
	printf("tcplib: completing data structure\n");
    ModuleConnFillcache();
    
    /* do TELNET */
    if (ldebug)
	printf("tcplib: running telnet\n");
    RunAllFour(tcplib_do_telnet_packetsize,TCPLIB_TELNET_PACKETSIZE_FILE);
    RunAllFour(tcplib_do_telnet_interarrival,TCPLIB_TELNET_INTERARRIVAL_FILE);
    RunAllFour(tcplib_do_telnet_duration,TCPLIB_TELNET_DURATION_FILE);



    /* do FTP */
    if (ldebug)
	printf("tcplib: running ftp\n");
    RunAllFour(tcplib_do_ftp_control_size,TCPLIB_FTP_CTRLSIZE_FILE);
    RunAllFour(tcplib_do_ftp_itemsize,TCPLIB_FTP_ITEMSIZE_FILE);
    RunAllFour(tcplib_do_ftp_numitems,TCPLIB_FTP_NITEMS_FILE);



    /* do SMTP */
    if (ldebug)
	printf("tcplib: running smtp\n");
    RunAllFour(tcplib_do_smtp_itemsize,TCPLIB_SMTP_ITEMSIZE_FILE);



    /* do NNTP */
    if (ldebug)
	printf("tcplib: running nntp\n");
    RunAllFour(tcplib_do_nntp_itemsize,TCPLIB_NNTP_ITEMSIZE_FILE);
    RunAllFour(tcplib_do_nntp_numitems,TCPLIB_NNTP_NITEMS_FILE);


    /* do HTTP */
    if (ldebug)
	printf("tcplib: running http\n");
    RunAllFour(tcplib_do_http_itemsize,TCPLIB_HTTP_ITEMSIZE_FILE);


    /* do the breakdown stuff */
    if (ldebug)
	printf("tcplib: running breakdowns\n");
    do_all_final_breakdowns();


    /* do the conversation interrival time */
    if (ldebug)
	printf("tcplib: running conversation interarrival times\n");
    do_all_conv_arrivals();
    for (i=0; i < NUM_TCB_TYPES; ++i) {
	if (ldebug>1)
	    printf("tcplib: running conversation arrivals (%s)\n",
		   ttype_names[i]);
	filename = namedfile(ttype_names[i],TCPLIB_NEXT_CONVERSE_FILE);
	do_tcplib_final_converse(filename,
				 global_pstats[i]->conv_interarrival);

	filename = namedfile(ttype_names[i],TCPLIB_CONV_DURATION_FILE);
	do_tcplib_conv_duration(filename,
				global_pstats[i]->conv_duration);

	if (LOCAL_ONLY)
	    break;
    }

    /* print stats */
    printf("tcplib: total connections seen: %lu (%lu accepted, %lu bad port)\n",
	   newconn_counter, newconn_goodport, newconn_badport);
    printf("tcplib: %lu random connections accepted under FTP data heuristic\n",
	   newconn_ftp_data_heuristic);
    for (i=0; i < NUM_TCB_TYPES; ++i) {
	printf("  Flows of type %-8s %5lu (%lu duplex, %lu noplex, %lu unidir, %lu nodata)\n",
	       ttype_names[i],
	       conntype_counter[i],
	       conntype_duplex_counter[i],
	       conntype_noplex_counter[i],
	       conntype_uni_counter[i],
	       conntype_nodata_counter[i]);
    }
    

    return;
}








/***************************************************************************
 * 
 * Function Name: tcplib_read
 * 
 * Returns: Nothing
 *
 * Purpose: This function is called each time a packet is read in by
 *          tcptrace.  tcplib_read examines the packet, and keeps track
 *          of certain information about the packet based on the packet's
 *          source and/or destination ports.
 *
 * Called by: ModulesPerPacket() in tcptrace.c
 * 
 * 
 ****************************************************************************/
void tcplib_read(
    struct ip *pip,    /* The packet */
    tcp_pair *ptp,     /* The pair of hosts - basically the conversation */
    void *plast,       /* Unused here */
    void *pmodstruct   /* Nebulous structure used to hold data that the module
			* feels is important. */
    )
{
    struct tcphdr *tcp;  /* TCP header information */
    int data_len = 0;    /* Length of the data cargo in the packet, and
			  * the period of time between the last two packets
			  * in a conversation */
    tcb *ptcb;
    module_conninfo_tcb *ptcbc;
    struct tcplibstats *pstats;
    module_conninfo *pmc = pmodstruct;
    enum t_statsix ttype;

    /* first, discard any connections that we aren't interested in. */
    /* That means that pmodstruct is NULL */
    if (pmc == NULL) {
	return;
    }


    /* Setting a pointer to the beginning of the TCP header */
    tcp = (struct tcphdr *) ((char *)pip + (4 * pip->ip_hl));

    /* calculate the amount of user data */
    data_len = pip->ip_len -	/* size of entire IP packet (and IP header) */
	(4 * pip->ip_hl) -	/* less the IP header */
	(4 * tcp->th_off);	/* less the TCP header */


    /* see which of the 2 TCB's this goes with */
    if (ptp->addr_pair.a_port == ntohs(tcp->th_sport)) {
	ptcb = &ptp->a2b;
	ptcbc = &pmc->tcb_cache_a2b;
    } else {
	ptcb = &ptp->b2a;
	ptcbc = &pmc->tcb_cache_b2a;
    }


    /* see where to keep the stats */
    ttype = traffic_type(pmc,ptcbc);
    pstats = global_pstats[ttype];

    /* Let's do the telnet packet sizes.  Telnet packets are the only
     * ones where we actually care about the sizes of individual packets.
     * All the other connection types are a "send as fast as possible" 
     * kind of setup where the packet sizes are always optimal.  Because
     * of this, we need the size of each and every telnet packet that 
     * comes our way. */
    if (is_telnet_conn(pmc)) {
	if (data_len > 0) {
	    if (ldebug>2)
		printf("read: adding %d byte telnet packet to %s\n",
		       data_len, ttype_names[ttype]);
	    tcplib_add_telnet_packetsize(pstats,data_len);
	}
    }


    /* Here's where we'd need to do telnet interarrival times.  The
     * same basic scenario applies with telnet packet interarrival
     * times.  Because telnet type traffic is "stop and go", we need
     * to be able to model how long the "stops" are.  So we measure
     * the time in between successive packets in a single telnet
     * conversation. */
    if (is_telnet_conn(pmc)) {
	tcplib_add_telnet_interarrival(
	    ptp, pmc, &pstats->telnet_interarrival);
    }
    pmc->last_time = current_time;


    /* keep track of bytes/second too */
    if (data_len > 0) {
	static timeval last_time = {0,0};
	unsigned etime;

	/* accumulate total bytes */
	pstats->throughput_bytes += data_len;

	/* elapsed time in milliseconds */
	etime = (int)(elapsed(last_time, ptp->last_time)/1000.0);

	/* every 15 seconds, gather throughput stats */
	if (etime > 15000) {
	    AddToCounter(&pstats->throughput,
			 pstats->throughput_bytes/1024, etime);
	    pstats->throughput_bytes = 0;
	    last_time = ptp->last_time;
	}

    }


    /* create data for traffic breakdown over time file */
    /* (sdo - only count packets with DATA) */
    if (data_len > 0) {
	int a2b_btype = pmc->btype;

	if (a2b_btype != TCPLIBPORT_NONE) {
	    pstats->tcplib_breakdown_interval[a2b_btype] +=
		ptp->a2b.data_bytes;
	}
    }

    /* DATA Burst checking */
    if (data_len > 0) {
	seqnum seq = ntohl(tcp->th_seq);

	/* NNTP burst checking */
	if (is_nntp_conn(pmc)) {
	    if (IsNewBurst(pmc, ptcb, seq)) {
		++ptcbc->numitems;
	    }
	}
    }

    /* This is just a sanity check to make sure that we've got at least
     * one time, and that our breakdown section is working on the same
     * file that we are. */
    data_len = (ptp->last_time.tv_sec - pstats->last_interval.tv_sec);
    
    if (data_len >= TIMER_VAL) {
	update_breakdown(ptp, pstats);
    }

    return;
}





/******************************************************************
 *
 * fill the tcb cache, make the 'previous' linked lists
 *
 ******************************************************************/
static void
ModuleConnFillcache(
    void)
{
    module_conninfo *pmc;
    enum t_statsix ttype;
    int i;

    /* fill the cache */
    for (pmc = module_conninfo_tail; pmc ; pmc=pmc->prev) {
	tcp_pair *ptp = pmc->ptp;	/* shorthand */
	int a2b_bytes = ptp->a2b.data_bytes;
	int b2a_bytes = ptp->b2a.data_bytes;

	/* both sides byte counters */
	pmc->tcb_cache_a2b.data_bytes = a2b_bytes;
	pmc->tcb_cache_b2a.data_bytes = b2a_bytes;

	/* debugging stats */
	if ((a2b_bytes == 0) && (b2a_bytes == 0)) {
	    /* no bytes at all */
	    ++conntype_noplex_counter[pmc->tcb_cache_a2b.ttype];
	    ++conntype_noplex_counter[pmc->tcb_cache_b2a.ttype];
	} else if ((a2b_bytes != 0) && (b2a_bytes == 0)) {
	    /* only A2B has bytes */
	    ++conntype_uni_counter[pmc->tcb_cache_a2b.ttype];
	    ++conntype_nodata_counter[pmc->tcb_cache_b2a.ttype];
	} else if ((a2b_bytes == 0) && (b2a_bytes != 0)) {
	    /* only B2A has bytes */
	    ++conntype_nodata_counter[pmc->tcb_cache_a2b.ttype];
	    ++conntype_uni_counter[pmc->tcb_cache_b2a.ttype];
	} else {
	    /* both sides have bytes */
	    ++conntype_duplex_counter[pmc->tcb_cache_a2b.ttype];
	    ++conntype_duplex_counter[pmc->tcb_cache_b2a.ttype];
	}

	    
	/* globals */
	pmc->last_time = ptp->last_time;
    }


    for (ttype = LOCAL; ttype <= REMOTE; ++ttype) {
	/* do the A sides, then the B sides */
	for (i=1; i <= 2; ++i) {
	    if (ldebug>1)
		printf("  Making previous for %s, side %s\n",
		       ttype_names[i], (i==1)?"A":"B");
	    for (pmc = module_conninfo_tail; pmc ; ) {
		module_conninfo_tcb *ptcbc;

		if (i==1) {
		    ptcbc = &pmc->tcb_cache_a2b;
		} else {
		    ptcbc = &pmc->tcb_cache_b2a;
		}

		if (ptcbc->ttype == ttype) {
		    module_conninfo *prev
			= FindPrevConnection(pmc,ttype);
		    ptcbc->prev_ttype = prev;
		    pmc = prev;
		} else {
		    pmc = pmc->prev;
		}
	    }
	}
    }
}



/******************************************************************
 *
 * to improve efficiency, we try to keep all of these on the
 * same virual pages
 *
 ******************************************************************/
static module_conninfo *
NewModuleConn()
{
#define CACHE_SIZE 128
    static module_conninfo *pcache[CACHE_SIZE];
    static int num_cached = 0;
    module_conninfo *p;

    if (num_cached == 0) {
	int i;
	char *ptmp;

	ptmp = MallocZ(CACHE_SIZE*sizeof(module_conninfo));

	for (i=0; i < CACHE_SIZE; ++i) {
	    pcache[i] = (module_conninfo *)ptmp;
	    ptmp += sizeof(module_conninfo);
	}

	num_cached = CACHE_SIZE;
    }

    /* grab one from the cache and return it */
    p = pcache[--num_cached];
    return(p);
}



/***************************************************************************
 * 
 * Function Name: tcplib_newconn
 * 
 * Returns: The time of this connection.  This becomes the pmodstruct that
 *          is returned with each call to tcplib_read.
 *
 * Purpose: To setup and handle new connections.
 *
 * Called by: ModulesPerConn() in tcptrace.c
 * 
 * 
 ****************************************************************************/
void *
tcplib_newconn(
    tcp_pair *ptp)   /* This conversation */
{
    int btype;			/* breakdown type */
    module_conninfo *pmc;
                                  /* Pointer to a timeval structure.  The
				   * timeval structure becomes the time of
				   * the last connection.  The pmc
				   * is tcptrace's way of allowing modules
				   * to keep track of information about
				   * connections */

    /* verify that it's a connection we're interested in! */
    ++newconn_counter;
    btype = breakdown_type(ptp);
    if (btype == TCPLIBPORT_NONE) {
	++newconn_badport;
	return(NULL); /* so we won't get it back in tcplib_read() */
    } else {
	/* else, it's acceptable, count it */
	++newconn_goodport;
    }


    /* create the connection-specific data structure */
    pmc = NewModuleConn();
    pmc->first_time = current_time;
    pmc->ptp = ptp;
    pmc->tcb_cache_a2b.ptcb = &ptp->a2b;
    pmc->tcb_cache_b2a.ptcb = &ptp->b2a;

    /* cache the address info */
    pmc->addr_pair = ptp->addr_pair;

    /* determine its "insideness" */
    pmc->tcb_cache_a2b.ttype = traffic_type(pmc, &pmc->tcb_cache_a2b);
    pmc->tcb_cache_b2a.ttype = traffic_type(pmc, &pmc->tcb_cache_b2a);
    ++conntype_counter[pmc->tcb_cache_a2b.ttype];
    ++conntype_counter[pmc->tcb_cache_b2a.ttype];

    /* determine the breakdown type */
    pmc->btype = btype;

    /* chain it in */
    pmc->prev = module_conninfo_tail;
    module_conninfo_tail = pmc;

    /* add to list of endpoints we track */
    TrackEndpoints(pmc);

    return (pmc);
}






/***************************************************************************
 * 
 * Function Name: tcplib_newfile
 * 
 * Returns: Nothing
 *
 * Purpose: This function is called by tcptrace every time that a new
 *          trace file is opened.  tcplib_newfile basically sets up a new
 *          line in the breakdown file, so that we can get a picture of
 *          the traffic distribution for a single trace.
 *
 * Called by: ModulesPerFile() in tcptrace.c
 * 
 * 
 ****************************************************************************/
void tcplib_newfile(
    char *filename,     /* Name of the file just opened. */
    u_long filesize,
    Bool fcompressed
    )
{
    static int first_file = TRUE;

    /* If this isn't the first file that we've seen this run, then
     * we want to run do_final_breakdown on the file we ran BEFORE
     * this one. */
    if (!first_file) {
	do_all_final_breakdowns();
	free(current_file);
    } else {
	/* If this is the first file we've seen, then we just want to 
	 * record the name of this file, and do nothing until the file
	 * is done. */
	printf("%s", filename);
	first_file = FALSE;
    }	

    /* remember the current file name */
    current_file = (char *) strdup(filename);

    setup_breakdown();

    return;
}







/***************************************************************************
 * 
 * Function Name: tcplib_usage
 * 
 * Returns: Nothing
 *
 * Purpose: To print out usage instructions for this module.
 *
 * Called by: ListModules() in tcptrace.c
 * 
 * 
 ****************************************************************************/
void tcplib_usage()
{
    printf("\
\t-xtcplib\"[ARGS]\"\tgenerate tcplib-format data files from trace\n");
    printf("\
\t  -oN      set port offset to N, default is 0\n\
\t           for example, we normally find telnet at 23, but\n\
\t           if it's at 9023, then use \"-o9000\"\n\
\t  -iIPLIST\n\
\t           define the IP addresses which are \"inside\".  Format allows\n\
\t           ranges and commas, as in:\n\
\t               -i128.1.0.0-128.2.255.255\n\
\t               -i128.1.0.0-128.2.255.255,192.10.1.0-192.10.2.240\n\
\t  -DDIR    store the results in directory DIR, default is \"data\"\n\
");
}

/* End of the tcptrace standard function section */








/***************************************************************************
 * 
 * Function Name: tcplib_init_setup
 * 
 * Returns: Nothing
 *
 * Purpose:  To setup and initialize the tcplib module's set of 
 *           global variables.
 *
 * Called by: tcplib_init() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
static void tcplib_init_setup(void)
{
    int i;   /* Loop Counter */
    enum t_statsix ix;
    struct tcplibstats *pstats;

    /* We need to save the contents in order to piece together the answers
     * later on
     *
     * sdo - so why does Eric turn it OFF?
     */
    save_tcp_data = FALSE;


    for (ix = LOCAL; ix <= REMOTE; ++ix) {
	/* create the big data structure */
	global_pstats[ix] = pstats = MallocZ(sizeof(struct tcplibstats));

	for(i = 0; i < NUM_APPS; i++) {
	    pstats->tcplib_breakdown_interval[i] = 0;
	}
    }

    setup_breakdown();

    return;
}



/***************************************************************************
 * 
 * Function Name: setup_breakdown
 * 
 * Returns: Nothing
 *
 * Purpose: To open the traffic breakdown graph file, and to set the
 *          interval count.
 *
 * Called by: tcplib_init_setup() in mod_tcplib.c
 *            tcplib_newfile()    in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
static void setup_breakdown(void)
{
    int ix;
    
    for (ix = LOCAL; ix <= REMOTE; ++ix) {
	struct tcplibstats *pstats = global_pstats[ix];
	char *prefix = ttype_names[ix];
	char *filename = namedfile(prefix,TCPLIB_BREAKDOWN_GRAPH_FILE);

	if (!(pstats->hist_file = fopen(filename, "w"))) {
	    perror(filename);
	    exit(1);
	}

	pstats->interval_count = 0;
    }
}




/***************************************************************************
 * 
 * Function Name: update_breakdown
 * 
 * Returns: Nothing
 *
 * Purpose: To create a file containing a kind of histogram of traffic
 *          seen in this file.  The histogram would contain one row per
 *          a set # of seconds, and would display one characteristic
 *          character per a specified number of bytes.
 *
 * Called by: tcplib_read() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
static void update_breakdown(
    tcp_pair *ptp,      /* This conversation */
    struct tcplibstats *pstats)
{
    int i;        /* Looping variable */
    int count;
    
    /* Displays the interval number.  A new histogram line is displayed
     * at TIMER_VALUE seconds. */
    fprintf(pstats->hist_file, "%d\t", pstats->interval_count);

    /* Display some characters for each type of traffic */
    for(i = 0; i < NUM_APPS; i++) {
	struct tcplibstats *pstats = global_pstats[LOCAL];

	/* We'll be displaying one character per BREAKDOWN_HASH number
	   of bytes */
	count = (pstats->tcplib_breakdown_interval[i] / BREAKDOWN_HASH) + 1;

	/* If there was actually NO traffic of that type, then we don't
	 * want to display any characters.  But if there was a little bit
	 * of traffic, even much less than BREAKDOWN_HASH, we want to 
	 * acknowledge it. */
	if (!pstats->tcplib_breakdown_interval[i])
	    count--;

	/* Print one hash char per count. */
	while(count > 0) {
	    fprintf(pstats->hist_file, "%c", breakdown_hash_char[i]);
	    count--;
	}
    }

    /* After we've done all the applications, end the line */
    fprintf(pstats->hist_file, "\n");

    /* Zero out the counters */
    for(i = 0; i < NUM_APPS; i++) {
	pstats->tcplib_breakdown_interval[i] = 0;
    }

    /* Update the breakdown interval */
    pstats->interval_count++;

    /* Update the time that the last breakdown interval occurred. */
    pstats->last_interval = current_time;
}



/***************************************************************************
 * 
 * Function Name: namedfile
 * 
 * Returns: Relative path name attached to output file name.
 *
 * Purpose: The namedfile uses the -D command line argument to take a data
 *          directory and puts it together with its default file name to
 *          come up with the file name needed for output.
 *
 * Called by: do_final_breakdown() in mod_tcplib.c
 *            do_tcplib_final_converse() in mod_tcplib.c
 *            tcplib_do_telnet_duration() in mod_tcplib.c
 *            tcplib_do_telnet_interarrival() in mod_tcplib.c
 *            tcplib_do_telnet_pktsize() in mod_tcplib.c
 *            tcplib_do_ftp_itemsize() in mod_tcplib.c
 *            tcplib_do_ftp_control_size() in mod_tcplib.c
 *            tcplib_do_smtp_itemsize() in mod_tcplib.c
 *            tcplib_do_nntp_itemsize() in mod_tcplib.c
 *            tcplib_do_http_itemsize() in mod_tcplib.c
 * 
 ****************************************************************************/
static char *
namedfile(
    char * localsuffix,
    char * real)  /* Default file name for the output file */
{
    char directory[256];
    static char buffer[256];    /* Buffer to store the full file name */

    if (!LOCAL_ONLY)
	sprintf(directory, "%s_%s", output_dir, localsuffix);
    else
	sprintf(directory, "%s", output_dir);

    /* try to CREATE the directory if it doesn't exist */
    if (access(directory,F_OK) != 0) {
	if (mkdir(directory,0755) != 0) {
	    perror(directory);
	    exit(-1);
	}
	if (ldebug>1)
	    printf("Created directory '%s'\n", directory);
    }

    sprintf(buffer, "%s/%s", directory, real);

    return buffer;
}




/***************************************************************************
 * 
 * Function Name: do_final_breakdown
 * 
 * Returns: Nothing
 *
 * Purpose: To generate the final breakdown file.  More specifically, to
 *          generate the one line in the breakdown file associated with
 *          the input file that is currently being traced.
 *
 * Called by: tcplib_done()    in mod_tcplib.c
 *            tcplib_newfile() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
static void do_final_breakdown(
    char *filename,
    f_testinside p_tester,
    struct tcplibstats *pstats)
{
    module_conninfo *pmc;
    FILE* fil;        /* File descriptor for the traffic breakdown file */
    long file_pos;    /* Offset within the traffic breakdown file */
    int i;


    /* This is the header for the traffic breakdown file.  It follows the
     * basic format of the original TCPLib breakdown file, but has been
     * modified to accomodate the additions that were made to TCPLib */
    char *header = "stub\tsmtp\tnntp\ttelnet\tftp\thttp\tphone\tconv\n";

    if (!(fil = fopen(filename, "a"))) {
	perror("Opening Breakdown File");
	exit(1);
    }

    fseek(fil, 0, SEEK_END);
    file_pos = ftell(fil);

    /* Basically, we're checking to see if this file has already been
     * used.  We have the capability to both start a new set of data
     * based on a trace file, or we have the ability to incorporate one
     * trace file's data into the data from another trace.  This would
     * have the effect of creating a hybrid traffic pattern, that matches
     * neither of the sources, but shares characteristics of both. */
    if (file_pos < strlen(header)) {
	fprintf(fil, "%s", header);
    }

    /* We only do this next part if we actually have a file name.  In
     * earlier revisions, sending a NULL filename signified the end of
     * all trace files.  At this point, a NULL file name has no useful
     * purpose, so we ignore it completely. */
    if (current_file) {
	int bad_port = 0;
	int no_data = 0;
	int bad_dir = 0;

	/* for protocol breakdowns */
	int breakdown_protocol[NUM_APPS] = {0};

	/* The breakdown file line associated with each trace file is
	 * prefaced with the trace file's name.  This was part of the
	 * original TCPLib format. */
	fprintf(fil, "%s", current_file);

	/* count the connections of each protocol type */
	for (pmc = module_conninfo_tail; pmc ; pmc = pmc->prev) {
	    int protocol_type;
	    module_conninfo_tcb *ptcbc;

	    /* check the protocol type */
	    protocol_type = pmc->btype;
	    if (protocol_type == TCPLIBPORT_NONE) {
		++bad_port;
		continue;	/* not interested, loop to next conn */
	    }

	    /* see if we want A->B */
	    ptcbc = &pmc->tcb_cache_a2b;
	    if ((*p_tester)(pmc, ptcbc)) {
		/* count it if there's data */
		if (ptcbc->data_bytes > 0) {
		    ++breakdown_protocol[protocol_type];
		} else {
		    ++no_data;
		}
	    } else {
		/* see if we want B->A */
		ptcbc = &pmc->tcb_cache_b2a;
		if ((*p_tester)(pmc, ptcbc)) {
		    /* count it if there's data */
		    if (ptcbc->data_bytes > 0) {
			++breakdown_protocol[protocol_type];
		    } else {
			++no_data;
		    }
		} else {
		    ++bad_dir;
		}
	    }
	}

	/* Print out the ratio of conversations of each traffic type
	 * to total number of converstaions observed in the trace file
	 */
	for(i = 0; i < NUM_APPS; i++) {
	    if (i == TCPLIBPORT_FTPDATA)
		continue;	/* we don't count this one */
	    
	    fprintf(fil, "\t%.4f",
		    ((float)breakdown_protocol[i])/
		    num_tcp_pairs);
#ifdef DEBUG
	    printf("letter[%c]: %d (%2f%%)\n",
		   breakdown_hash_char[i],
		   breakdown_protocol[i],
		   (100.0*(float)breakdown_protocol[i])/
		    num_tcp_pairs);
#endif DEBUG
	}

#ifdef DEBUG
	printf("Bad_port: %d\n", bad_port);
	printf("no_data: %d\n", no_data);
	printf("bad_dir: %d\n", bad_dir);
#endif DEBUG


	/* Place holders for phone and converstation intervals.  The
	 * phone type was never fully developed in the original TCPLib
	 * implementation.  At the current time, we don't consider
	 * phone type conversations.  The placeholder for conversation
	 * intervals allows us to use TCPLib's existing setup for
	 * aquiring statistics.  Without a placeholder in the
	 * breakdown file, TCPLib won't recognize this particular
	 * item, and in the generation of statistically equivalent
	 * traffic patterns, the interval between converstaions is of
	 * utmost importance, especially as far as the scalability of
	 * traffic is concerned. */
	fprintf(fil, "\t%.4f\t%.4f\n", (float)0, (float)0);

    }

    fclose(fil);
    fclose(pstats->hist_file);
}

static void do_all_final_breakdowns(void)
{
    char *filename;
    
    filename = namedfile("local",TCPLIB_BREAKDOWN_FILE);
    do_final_breakdown(filename, TestLocal,
		       global_pstats[LOCAL]);

    if (LOCAL_ONLY)
	return;  /* none of the rest will match anyway */

    filename = namedfile("incoming",TCPLIB_BREAKDOWN_FILE);
    do_final_breakdown(filename, TestIncoming,
		       global_pstats[INCOMING]);

    filename = namedfile("outgoing",TCPLIB_BREAKDOWN_FILE);
    do_final_breakdown(filename, TestOutgoing,
		       global_pstats[OUTGOING]);

    filename = namedfile("remote",TCPLIB_BREAKDOWN_FILE);
    do_final_breakdown(filename, TestRemote,
		       global_pstats[REMOTE]);
}



/***************************************************************************
 * 
 * Function Name: breakdown_type
 * 
 * Returns: The generic type of connection associated with "port"
 *
 * Purpose: To convert the port given to the function to the appropriate
 *          TCPLib type port.  As we come across other ports that have the
 *          same basic characteristics as TCPLib type, we can just add
 *          them here.
 *
 * Called by: tcplib_read()        in mod_tcplib.c
 *            do_final_breakdown() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
static int breakdown_type(
    tcp_pair *ptp)
{
    /* shorthand */
    portnum porta = ptp->addr_pair.a_port;
    portnum portb = ptp->addr_pair.b_port;

    if (is_telnet_port(porta) || 
	is_telnet_port(portb))
	return(TCPLIBPORT_TELNET);

    if (is_ftp_ctrl_port(porta) ||
	is_ftp_ctrl_port(portb))
	return(TCPLIBPORT_FTPCTRL);

    if (is_smtp_port(porta) ||
	is_smtp_port(portb))
	return(TCPLIBPORT_SMTP);

    if (is_nntp_port(porta) ||
	is_nntp_port(portb))
	return(TCPLIBPORT_NNTP);

    if (is_http_port(porta) ||
	is_http_port(portb))
	return(TCPLIBPORT_HTTP);
    
    if (is_ftp_data_port(porta) ||
	is_ftp_data_port(portb) ||
	CouldBeFtpData(ptp))
	return(TCPLIBPORT_FTPDATA);

    return TCPLIBPORT_NONE;
}

/* End Breakdown Stuff */







/* Begin Next Conversation Stuff */

/***************************************************************************
 * 
 * Function Name: do_tcplib_next_converse
 * 
 * Returns: Nothing
 *
 * Purpose: This function takes a new conversation and deals with the time
 *          between successive conversations.  If an entry in the breakdown
 *          table already exists with that particular time, then the counter
 *          is simply incremented.  If not, then a new table is made with a
 *          space for the new table item.  We're using arrays, but a change
 *          might be made to use a linked list before too long.
 *
 * Called by: tcplib_newconn() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
static void do_tcplib_next_converse(
    module_conninfo_tcb *ptcbc,
    module_conninfo *pmc)
{
    struct tcplibstats *pstats;
    module_conninfo *pmc_previous;
    enum t_statsix ttype;
    int etime;   /* Time difference between the first packet in this
		  * conversation and the first packet in the previous
		  * conversation.  Basically, this is the time between
		  * new conversations. */

    /* see where to keep the stats */
    ttype = traffic_type(pmc, ptcbc);
    pstats = global_pstats[ttype];

    if (ldebug>2) {
	printf("do_tcplib_next_converse: %s, %s\n",
	       FormatBrief(pmc->ptp), ttype_names[ttype]);
    }


    /* sdo - Wed Jun 16, 1999 */
    /* new method, search backward to find the previous connection that had */
    /* data flowing in the same "direction" and then use the difference */
    /* between the starting times of those two connections as the conn */
    /* interrival time */
    /* sdo - Fri Jul  9, 1999 (information already computed in Fillcache) */
    pmc_previous = ptcbc->prev_ttype;


    if (pmc_previous == NULL) {
	/* no previous connection, this must be the FIRST in */
	/* this direction */
	if (ldebug>2) {
	    printf("    do_tcplib_next_converse: no previous\n");
	}
	return;
    }


    /* elapsed time since that previous connection started */
    etime = (int)(elapsed(pmc_previous->first_time,
			  pmc->first_time)/1000.0); /* convert us to ms */

    if (ldebug>2) {
	printf("   prev: %s, etime: %d ms\n",
	       FormatBrief(pmc_previous->ptp), etime);
    }

    /* keep stats */
    AddToCounter(&pstats->conv_interarrival, etime, 1);
    
    return;
}

/* End of the breakdown section */


/* return the previous connection that passes data in the direction */
/* given in "ttype" */
module_conninfo *
FindPrevConnection(
    module_conninfo *pmc,
    enum t_statsix ttype)
{
    module_conninfo_tcb *ptcbc;
    int count = 0;

    /* loop back further in time */
    for (pmc = pmc->prev; pmc; pmc = pmc->prev) {
	ptcbc = &pmc->tcb_cache_a2b;
	if (ptcbc->ttype == ttype) {
	    if (ptcbc->data_bytes != 0)
		return(pmc);
	}

	ptcbc = &pmc->tcb_cache_b2a;
	if (ptcbc->ttype == ttype) {
	    if (ptcbc->data_bytes != 0)
		return(pmc);
	}

	if (ldebug)
	    ++count;
    }

    if (ldebug > 1)
	printf("FindPrevConnection %s returned NULL, took %d searches\n",
	       ttype_names[ttype], count);

    return(NULL);
}



/***************************************************************************
 * 
 * Function Name: do_tcplib_final_converse
 * 
 * Returns: Nothing
 *
 * Purpose: To generate a new line in the breakdown file which shows the
 *          conversation percentages viewed in the file that is currently
 *          open, but has just been ended.
 *
 * Called by: tcplib_done() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
static void
do_tcplib_final_converse(
    char *filename,
    dyn_counter psizes)
{
    const int bucketsize = 1;


    /* sdo - OK, pstats->conv_interarrival already has the counts we */
    /* made.  First, include anything from an existing file. */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* Now, dump out the combined data */
    StoreCounters(filename,"Conversation Interval Time (ms)",
		  "% Interarrivals", bucketsize, psizes);

    return;
}

static void
do_tcplib_conv_duration(
    char *filename,
    dyn_counter psizes)
{
    const int bucketsize = 50;

    psizes = ReadOldFile(filename, bucketsize, 0, psizes);

    /* Now, dump out the combined data */
    StoreCounters(filename,"Conversation Duration (ms)",
		  "% Conversations", bucketsize, psizes);

    return;
}

static void do_tcplib_next_duration(
    module_conninfo_tcb *ptcbc,
    module_conninfo *pmc)
{
    struct tcplibstats *pstats;
    enum t_statsix ttype;
    int etime;   /* Time difference between the first packet in this
		  * conversation and the last packet */

    /* see where to keep the stats */
    ttype = traffic_type(pmc, ptcbc);
    pstats = global_pstats[ttype];

    if (ldebug>2) {
	printf("do_tcplib_next_duration: %s, %s\n",
	       FormatBrief(pmc->ptp), ttype_names[ttype]);
    }


    /* elapsed time since that previous connection started */
    etime = (int)(elapsed(pmc->first_time,
			  pmc->last_time)/1000.0); /* convert us to ms */

    /* keep stats */
    AddToCounter(&pstats->conv_duration, etime, 1);
    
    return;
}

/* End Next Conversation Stuff */










/* Begin Telnet stuff */

/***************************************************************************
 * 
 * Function Name: is_telnet_port
 * 
 * Returns: TRUE/FALSE whether a given port is a telnet/login type port.
 *
 * Purpose: To accept a port number and determine whenter or not the port
 *          would exhibit the characteristics of a telnet/login port.
 *
 * Called by: tcplib_read()                in mod_tcplib.c
 *            tcplib_do_telnet_duration()  in mod_tcplib.c
 *            tcplib_add_telnet_interval() in mod_tcplib.c
 * 
 ****************************************************************************/
Bool is_telnet_port(
    portnum port)       /* The port we're looking at */
{
    port -= ipport_offset;

    switch(port) {
      case IPPORT_LOGIN:
      case IPPORT_KLOGIN:
      case IPPORT_OLDLOGIN:
      case IPPORT_FLN_SPX:
      case IPPORT_UUCP_LOGIN:
      case IPPORT_KLOGIN2:
      case IPPORT_NLOGIN:
      case IPPORT_TELNET:
      case IPPORT_SSH:
	return TRUE;
	break;

      default:
	return FALSE;
    }
}








/***************************************************************************
 * 
 * Function Name: tcplib_do_telnet_duration
 * 
 * Returns: Nothing
 *
 * Purpose: To collect information about the duration of a telnet
 *          conversation, and merge this information with data from
 *          previous runs of this module, if such data exists.
 *
 * Called by: tcplib_do_telnet() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
void tcplib_do_telnet_duration(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    dyn_counter psizes = NULL;
    const int bucketsize = 10;	/* 10 millisecond buckets */
    module_conninfo *pmc;
    

    /* This section reads in the data from the existing telnet duration
     * file in preparation for merging with the current data. */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* Fill the array with the current data */
    for (pmc = module_conninfo_tail; pmc; pmc=pmc->prev) {
	/* if there wasn't data flowing in this direction, skip it */
	if (InsideBytes(pmc,p_tester) == 0)
	    continue;

	
	/* Only work this for telnet connections */
	if (is_telnet_conn(pmc)) {
	    /* convert the time difference to ms */
	    int temp = (int)(
		elapsed(pmc->first_time,
			pmc->last_time)/1000.0); /* convert us to ms */

	    /* increment the number of instances at this time. */
	    AddToCounter(&psizes, temp/bucketsize, 1);
	}
    }


    /* Output data to the file */
    StoreCounters(filename,"Duration (ms)", "% Conversations",
		  bucketsize,psizes);

    /* free the dynamic memory */
    DestroyCounters(&psizes);
}



/***************************************************************************
 * 
 * Function Name: do_all_conv_arrivals
 * 
 * Returns: Nothing
 *
 * Purpose: collect all the conversation interarrival times
 *
 * Called by: tcplib_done mod_tcplib.c
 * 
 * 
 ****************************************************************************/
void do_all_conv_arrivals()
{
    module_conninfo *pmc;

    if (ldebug>1)
	printf("do_all_conv_arrivals: there are %d tcp pairs\n",
	       num_tcp_pairs);

    /* process each connection */
    for (pmc = module_conninfo_tail; pmc; pmc=pmc->prev) {

	if (ldebug>2) {
	    static int count = 0;
	    printf("do_all_conv_arrivals: processing pmc %d: %p\n",
		   ++count, pmc);
	}

	/* A --> B */
	if (pmc->tcb_cache_a2b.data_bytes != 0) {
	    do_tcplib_next_converse(&pmc->tcb_cache_a2b, pmc);
	    do_tcplib_next_duration(&pmc->tcb_cache_a2b, pmc);
	}

	/* B --> A */
	if (pmc->tcb_cache_b2a.data_bytes != 0) {
	    do_tcplib_next_converse(&pmc->tcb_cache_b2a, pmc);
	    do_tcplib_next_duration(&pmc->tcb_cache_b2a, pmc);
	}
    }
}









/***************************************************************************
 * 
 * Function Name: tcplib_add_telnet_interarrival
 * 
 * Returns: Nothing
 *
 * Purpose: This function takes the current packet and computes the time
 *          between the current packet and the previous packet.  This value
 *          is then added to the list of telnet interarrivals.  These values
 *          will be used at a later time.
 *
 * Called by: tcplib_read() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
void tcplib_add_telnet_interarrival(
    tcp_pair *ptp,              /* This conversation */
    module_conninfo *pmc,
    dyn_counter *psizes)
{
    int temp = 0;    /* time differential between packets */

    /* Basically, I need the current time AND the time of the previous
     * packet BOTH right now.  As far as I can see, this function
     * won't get called until the previous packet time has already
     * been overwritten by the current time.  This makes obtaining
     * interarrival times more difficult.  */

    /* Answer - changed the original program.  We added the pmstruct thing
     * to the original TCPTrace which allows a module to store information
     * about a connection.  Quite handy.  Thanks, Dr. Ostermann */

    /* First packet has no interarrival time */
    if (tv_same(ptp->last_time,ptp->first_time)) {
	/* If this is the first packet we've seen, nothing to do.
	 * We'll be able to get some data the next
	 * time. */
	return;
    }
	
    /* Determining the time difference in ms */
    temp = (int)(elapsed(pmc->last_time, current_time)/1000.0); /* us to ms */

    /* We're going to set an artificial maximum for telnet interarrivals
     * for the case when someone (like me) would open a telnet session
     * and just leave it open and not do anything on it for minutes or
     * hours, or in some cases days.  Keeping track of the exact time
     * for a connection like that is not worth the effort, so we just
     * set a ceiling and if it's over the ceiling, we make it the
     * ceiling. */
    if (temp > MAX_TEL_INTER_COUNT - 1)
	temp = MAX_TEL_INTER_COUNT - 1;

    /* In this case, we know for a fact that we don't have a value of
     * temp that larger than the array, so we just increment the count
     */
    (void) AddToCounter(psizes, temp, 1);

    return;
}









    
/***************************************************************************
 * 
 * Function Name: tcplib_do_telnet_interarrival
 * 
 * Returns: Nothing
 *
 * Purpose: To model integrate the old data for telnet interarrival times
 *          with the data gathered during this execution of the program.
 *
 * Called by: tcplib_do_telnet() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
void tcplib_do_telnet_interarrival(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* stuck with the interface :-(  */
{
    const int bucketsize = 1;	/* 1 ms buckets */
    dyn_counter psizes = NULL;

    /* ugly interface conversion :-( */
    if (p_tester == TestIncoming)
	psizes = global_pstats[INCOMING]->telnet_interarrival;
    else if (p_tester == TestOutgoing)
	psizes = global_pstats[OUTGOING]->telnet_interarrival;
    else if (p_tester == TestLocal)
	psizes = global_pstats[LOCAL]->telnet_interarrival;
    else if (p_tester == TestRemote)
	psizes = global_pstats[REMOTE]->telnet_interarrival;
    else {
	fprintf(stderr,
		"tcplib_do_telnet_interarrival: internal inconsistancy!\n");
	exit(-1);
    }



    /* add in the data from the old run (if it exists) */
    psizes = ReadOldFile(filename, bucketsize, MAX_TEL_INTER_COUNT, psizes);


    /* Dumping the data out to the data file */
    StoreCounters(filename, "Interarrival Time (ms)", "% Interarrivals",
		  bucketsize,psizes);
}





/***************************************************************************
 * 
 * Function Name: tcplib_do_telnet_packetsize
 * 
 * Returns: Nothing
 *
 * Purpose: To take the data on telnet packet sizes measured during this
 *          run of the program, merge them with any existing data, and 
 *          drop a data file.
 *
 * Called by: tcplib_do_telnet() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
void tcplib_do_telnet_packetsize(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* stuck with the interface :-(  */
{
    const int bucketsize = 1;	/* 10 byte buckets */
    dyn_counter psizes = NULL;

    /* ugly interface conversion :-( */
    if (p_tester == TestIncoming)
	psizes = global_pstats[INCOMING]->telnet_pktsize;
    else if (p_tester == TestOutgoing)
	psizes = global_pstats[OUTGOING]->telnet_pktsize;
    else if (p_tester == TestLocal)
	psizes = global_pstats[LOCAL]->telnet_pktsize;
    else if (p_tester == TestRemote)
	psizes = global_pstats[REMOTE]->telnet_pktsize;
    else {
	fprintf(stderr,
		"tcplib_do_telnet_packetsize: internal inconsistancy!\n");
	exit(-1);
    }


    /* In this section, we're reading in from the previous data file,
     * applying the data contained there to the data set that we've 
     * acquired during this run, and then dumping the merged data set
     * back out to the data file */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* Dumping the data out to the data file */
    StoreCounters(filename, "Packet Size (bytes)", "% Packets",
		  bucketsize,psizes);
}








/***************************************************************************
 * 
 * Function Name: tcplib_add_telnet_packetsize
 * 
 * Returns: Nothing
 *
 * Purpose: Takes a length as acquired from a telnet packet data size and
 *          increments the count of the telnet packet size table by one for
 *          entry which corresponds to that length.  If the packet size is
 *          larger than the allocated table allows, we truncate the packet
 *          size.
 *
 * Called by: tcplib_read() in mod_tcplib.c
 * 
 * 
 ****************************************************************************/
void tcplib_add_telnet_packetsize(
    struct tcplibstats *pstats,
    int length)  /* The length of the packet to be added to the table */
{
    /* Incrementing the table */
    AddToCounter(&pstats->telnet_pktsize, length, 1);
}


/* End Telnet Stuff */








/* Begin FTP Stuff */

/***************************************************************************
 * 
 * Function Name: is_ftp_data_conn
 * 
 * Returns: Boolean value.
 *
 * Purpose: To determine if the connection is an FTP data port.
 *
 * Called by: tcplib_do_ftp_itemsize() in mod_tcplib.c
 * 
 ****************************************************************************/
#ifdef OLD
Bool is_ftp_data_port(
    portnum port)
{
    port -= ipport_offset;
    return (port == IPPORT_FTP_DATA);
}
#endif



/***************************************************************************
 * 
 * Function Name: is_ftp_ctrl_conn
 * 
 * Returns: Boolean value
 *
 * Purpose: To determine if the connection is an FTP control port.
 *
 * Called by: tcplib_do_ftp_control_size() in mod_tcplib.c
 * 
 ****************************************************************************/
Bool is_ftp_ctrl_port(
    portnum port)
{
    port -= ipport_offset;
    return (port == IPPORT_FTP_CONTROL);
}
Bool is_ftp_data_port(
    portnum port)
{
    port -= ipport_offset;
    return (port == IPPORT_FTP_DATA);
}

	    



/***************************************************************************
 * 
 * Function Name: tcplib_do_ftp_itemsize
 * 
 * Returns: Nothing
 *
 * Purpose: To generate the ftp.itemsize data file from the information
 *          collected on ftp transfer sizes.  This function also integrates
 *          new data with old data, if any old data exists.
 *
 * Called by: tcplib_do_ftp() in mod_tcplib.c
 * 
 ****************************************************************************/
void tcplib_do_ftp_itemsize(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 256;	/* 256-byte buckets */

    tcplib_do_GENERIC_itemsize(filename, TCPLIBPORT_FTPDATA,
			       p_tester, bucketsize);
}


void tcplib_do_ftp_numitems(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    int bucketsize = 1;
    module_conninfo *pmc;
    dyn_counter psizes = NULL;
    

    /* If an old data file exists, open it, read in its contents
     * and store them until they are integrated with the current
     * data */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* fill out the array with data from the current connections */
    for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	/* We only need the stats if it's the right port */
	if (is_ftp_ctrl_conn(pmc)) {
	    if ((*p_tester)(pmc, &pmc->tcb_cache_a2b)) {
		if (ldebug && (pmc->tcb_cache_a2b.numitems == 0))
			printf("numitems: control %s has NONE\n",
			       FormatBrief(pmc->ptp));
		AddToCounter(&psizes, pmc->tcb_cache_a2b.numitems, 1);
	    }
	}
    }


    /* store all the data (old and new) into the file */
    StoreCounters(filename,"Total Articles", "% Conversation",
		  bucketsize,psizes);

    /* free the dynamic memory */
    DestroyCounters(&psizes);
}


static void tcplib_do_ftp_control_size(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 10;	/* 10 byte buckets */

    tcplib_do_GENERIC_itemsize(filename, TCPLIBPORT_FTPCTRL,
			       p_tester, bucketsize);
}
/* End of FTP Stuff */




/* Begin SMTP Stuff */
static Bool
is_smtp_port(
    portnum port)
{
    port -= ipport_offset;
    return (port == IPPORT_SMTP);
}


static void tcplib_do_smtp_itemsize(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 10;	/* 10 byte buckets */

    tcplib_do_GENERIC_itemsize(filename, TCPLIBPORT_SMTP,
			       p_tester, bucketsize);
}
/* Done SMTP Stuff */




/* Begin NNTP Stuff */
static Bool
is_nntp_port(
    portnum port)
{
    port -= ipport_offset;
    return (port == IPPORT_NNTP);
}



static void tcplib_do_nntp_itemsize(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 10;	/* 10 byte buckets */

    tcplib_do_GENERIC_itemsize(filename, TCPLIBPORT_NNTP,
			       p_tester, bucketsize);
}


static void
tcplib_do_nntp_numitems(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    tcplib_do_GENERIC_numitems(filename, TCPLIBPORT_NNTP, p_tester);
}
/* Done NNTP Stuff */



/* Begin HTTP Stuff */
static Bool
is_http_port(
    portnum port)
{
    port -= ipport_offset;
    return ((port == IPPORT_HTTP) ||
	    (port == IPPORT_HTTPS));
}


static void tcplib_do_http_itemsize(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 10;  /* 10 byte buckets */

    tcplib_do_GENERIC_itemsize(filename, TCPLIBPORT_HTTP,
			       p_tester, bucketsize);
}


/***************************************************************************
 **
 ** Support Routines
 **
 ***************************************************************************/


static void
StoreCounters(
    char *filename,
    char *header1,
    char *header2,
    int bucketsize,
    dyn_counter psizes)
{
    FILE *fil;
    int running_total = 0;
    int lines = 0;

    if (ldebug>1)
	printf("Saving data for file '%s'\n", filename);

    if (!(fil = fopen(filename, "w"))) {
	perror(filename);
	exit(1);
    }

    fprintf(fil, "%s\t%s\tRunning Sum\tCounts\n", header1, header2);

    if (psizes == NULL) {
	if (ldebug>1)
	    printf("  (No data for file '%s')\n", filename);
    } else {
	int cookie = 0;
	while (1) {
	    u_long ix;
	    int value;
	    u_long count;

	    if (NextCounter(&psizes, &cookie, &ix, &count) == 0)
		break;

	    value = ix * bucketsize;
	    running_total += count;

	    if (count) {
		fprintf(fil, "%.3f\t%.4f\t%d\t%lu\n",
			(float)value, /* sdo bugfix */
			(((float)running_total)/((float)TotalCounter(psizes))),
			running_total,
			count);
		++lines;
	    }
	}
    }

    fclose(fil);

    if (ldebug)
	printf("  Stored %d values into %d lines of '%s'\n",
	       running_total, lines, filename);
}


static dyn_counter 
ReadOldFile(
    char *filename,
    int bucketsize,
    int maxlegal,		/* upper limit on array IX (or 0) */
    dyn_counter psizes)
{
    FILE* old;                /* File pointer for old data file */
    float bytes;
    int count;
    int linesread = 0;

    /* If the an old data file exists, open it, read in its contents
     * and store them until they are integrated with the current
     * data */
    if ((old = fopen(filename, "r"))) {
	char buffer[256];

	/* read and discard the first line */
	fgets(buffer, sizeof(buffer)-1, old);


	/* Read in each line in the file and pick out the pieces of */
	/* the file.  Store each important piece is psizes */
	/* format is: 
		Total Bytes	% Conversations	Running Sum	Counts
		5.000		0.0278		1		1
		170.000		0.1111		4		3
	*/
	/* (we only need the 1st and 4th fields) */
	while (fscanf(old, "%f\t%*f\t%*d\t%d\n", &bytes, &count) == 4) {
	    ++linesread;
	    if ((maxlegal != 0) && (bytes > maxlegal))
		bytes = maxlegal;
	    AddToCounter(&psizes, (((int)bytes)/bucketsize), count);
	}

	if (ldebug>2) {
	    if (psizes && (linesread > 0))
		printf("Read data from old file '%s' (%lu values)\n",
		       filename, TotalCounter(psizes));
	    else
		printf("Old data file '%s' had no data\n", filename);
	}

	fclose(old);
    }

    return(psizes);
}


/* all of the itemsize routines look like this */
static void
tcplib_do_GENERIC_itemsize(
    char *filename,		/* where to store the output */
    int btype,
    f_testinside p_tester,	/* functions to test "insideness" */
    int bucketsize)		/* how much data to group together */
{
    module_conninfo *pmc;
    dyn_counter psizes = NULL;
    

    /* If an old data file exists, open it, read in its contents
     * and store them until they are integrated with the current
     * data */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* fill out the array with data from the current connections */
    for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	/* We only need the stats if it's the right breakdown type */
	if (pmc->btype == btype) {
	    int nbytes = InsideBytes(pmc,p_tester);

	    /* if there's no DATA, don't count it!  (sdo change!) */
	    if (nbytes != 0)
		AddToCounter(&psizes, nbytes/bucketsize, 1);
	}
    }


    /* store all the data (old and new) into the file */
    StoreCounters(filename,"Article Size (bytes)", "% Articles",
		  bucketsize,psizes);

    /* free the dynamic memory */
    DestroyCounters(&psizes);
}


/* both ftp and nntp look the same */
static void
tcplib_do_GENERIC_numitems(
    char *filename,		/* where to store the output */
    int btype,
    f_testinside p_tester)
{
    int bucketsize = 1;
    module_conninfo *pmc;
    dyn_counter psizes = NULL;
    

    /* If an old data file exists, open it, read in its contents
     * and store them until they are integrated with the current
     * data */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* fill out the array with data from the current connections */
    for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	/* We only need the stats if it's the right port */
	if (pmc->btype == btype) {
	    if ((*p_tester)(pmc, &pmc->tcb_cache_a2b)) {
		if (ldebug && (pmc->tcb_cache_a2b.numitems == 0))
			printf("numitems: control %s has NONE\n",
			       FormatBrief(pmc->ptp));
		AddToCounter(&psizes, pmc->tcb_cache_a2b.numitems, 1);
	    }
	    if ((*p_tester)(pmc, &pmc->tcb_cache_b2a)) {
		if (ldebug && (pmc->tcb_cache_b2a.numitems == 0))
		    printf("numitems: control %s has NONE\n",
			   FormatBrief(pmc->ptp));
		AddToCounter(&psizes, pmc->tcb_cache_b2a.numitems, 1);
	    }
	}
    }


    /* store all the data (old and new) into the file */
    StoreCounters(filename,"Total Articles", "% Conversation",
		  bucketsize,psizes);

    /* free the dynamic memory */
    DestroyCounters(&psizes);
}


static enum t_statsix
traffic_type(
    module_conninfo *pmc,
    module_conninfo_tcb *ptcbc)
{
    if (TestLocal(pmc,ptcbc))
	return(LOCAL);

    if (TestIncoming(pmc,ptcbc))
	return(INCOMING);

    if (TestOutgoing(pmc,ptcbc))
	return(OUTGOING);

    if (TestRemote(pmc,ptcbc))
	return(REMOTE);

    fprintf(stderr,"Internal error in traffic_type\n");
    exit(-1);
}

static char *
FormatBrief(
    tcp_pair *ptp)
{
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;
    static char infobuf[100];

    sprintf(infobuf,"%s - %s (%s2%s)",
	    ptp->a_endpoint, ptp->b_endpoint,
	    pab->host_letter, pba->host_letter);
    return(infobuf);
}

static char *
FormatAddrBrief(
    tcp_pair_addrblock	*paddr_pair)
{
    static char infobuf[100];
    char infobuf1[100];
    char infobuf2[100];

    sprintf(infobuf1,"%s", HostName(paddr_pair->a_address));
    sprintf(infobuf2,"%s", HostName(paddr_pair->b_address));
    sprintf(infobuf,"%s - %s", infobuf1, infobuf2);

    return(infobuf);
}


/* find a connection pair */
static endpoint_pair *
FindEndpointPair(
    endpoint_pair *hashtable[],
    tcp_pair_addrblock	*paddr_pair)
{
    endpoint_pair **ppep_head;
    endpoint_pair *pep_search;

    /* find the correct hash bucket */
    ppep_head = &hashtable[EndpointHash(paddr_pair)];

    /* search the bucket for the correct pair */
    for (pep_search = *ppep_head; pep_search;
	 pep_search = pep_search->pepnext) {

	/* see if it's the same connection */
	if (SameEndpoints(&pep_search->addr_pair,
			  paddr_pair))
	    return(pep_search);
    }

    /* after loop, pep_search is NON-NULL if we found it */

    return(NULL);
}




/* add a connection to the list of all connections on that address pair */
static void
AddEndpointPair(
    endpoint_pair *hashtable[],
    module_conninfo *pmc)
{
    endpoint_pair **ppep_head;
    endpoint_pair *pep_search;

    /* search the bucket for the correct pair */
    ppep_head = &hashtable[EndpointHash(&pmc->addr_pair)];
    pep_search = FindEndpointPair(hashtable,&pmc->addr_pair);

    if (pep_search == NULL) {
	/* not found, create it */
	pep_search = MallocZ(sizeof(endpoint_pair));

	/* fill in the address info */
	pep_search->addr_pair = pmc->ptp->addr_pair;

	/* put at the front of the bucket */
	pep_search->pepnext = *ppep_head;
	*ppep_head = pep_search;
    }

    /* put the new connection at the front of the list for this
       endpoint pair */
    pmc->next_pair = pep_search->pmchead;
    pep_search->pmchead = pmc;

    if (ldebug>1) {
	printf("\nEndpoint pair bucket\n");

	/* for each thing on the bucket list */
	for (pep_search = *ppep_head; pep_search;
	     pep_search = pep_search->pepnext) {
	    module_conninfo *pmc;
	    printf("  %s:\n", FormatAddrBrief(&pep_search->addr_pair));
	    /* for each connection on that pair */
	    for (pmc = pep_search->pmchead; pmc; pmc = pmc->next_pair) {
		printf("    %u <-> %u\n",
		       pmc->addr_pair.a_port,
		       pmc->addr_pair.b_port);
	    }
	}
    }
}

static void
TrackEndpoints(
    module_conninfo *pmc)
{
    if (is_ftp_ctrl_conn(pmc)) {
	AddEndpointPair(ftp_endpoints,pmc);
    }

    /* if it's an FTP data connection, find the control conn */
    if (is_ftp_data_conn(pmc)) {
	endpoint_pair *pep;

	pep = FindEndpointPair(ftp_endpoints, &pmc->addr_pair);

	if (pep) {
	    /* "charge" this new DATA connection to the most
	       recently-active ftp control connection */
	    struct module_conninfo_tcb *tcbc_control;
	    tcbc_control = MostRecentFtpControl(pep);
	    ++tcbc_control->numitems;
	    if (ldebug) {
		printf("Charging ftp data to %s, count %lu\n",
		       FormatBrief(tcbc_control->ptcb->ptp),
		       tcbc_control->numitems);
	    }
	} else {
	    fprintf(stderr,"WARNING: no FTP control conn for %s???\n",
		    FormatBrief(pmc->ptp));
	}

    }

}


/* could this connection be an FTP data connection that's NOT
   on port 21? */
static Bool
CouldBeFtpData(
    tcp_pair *ptp)
{
    endpoint_pair *pep;
    struct module_conninfo_tcb *ptcbc;

    /* make sure NEITHER port is reserved */
    if (ptp->addr_pair.a_port < 1024 ||
	ptp->addr_pair.b_port < 1024)
	return(FALSE);
    
    /* see if there's any active FTP control connection on
       these endpoints... */
    pep = FindEndpointPair(ftp_endpoints,&ptp->addr_pair);
    if (pep == NULL)
	return(FALSE);

    /* find the most recent FTP control connection */
    ptcbc = MostRecentFtpControl(pep);
    if (pep == NULL)
	return(FALSE);

    /* OK, I guess it COULD be... */
    ++newconn_ftp_data_heuristic;
    return(TRUE);
}


/* find the TCB (client side) for the most recently-active control
   connection on this pair of endpoints */
static module_conninfo_tcb *
MostRecentFtpControl(
    endpoint_pair *pep)
{
    struct module_conninfo *pmc;
    static module_conninfo_tcb *tcbc_newest = NULL;
    tcb *tcb_newest;
    timeval time_newest;

    if (pep->pmchead == NULL) {
	/* None at all, that's odd... */
	fprintf(stderr,"MostRecentFtpControl: unexpected empty list \n");
	exit(-1);
    }


    /* search the rest looking for something newer */
    for (pmc = pep->pmchead; pmc; pmc = pmc->next_pair) {
	tcb *ptcb_client = &pmc->ptp->a2b;

	/* if it's not "active", we're not interested */
	if (!ActiveConn(pmc))
	    continue;

	/* have we found anyone yet? */
	if (tcbc_newest == NULL) {
	    tcb_newest = &pmc->ptp->a2b;
	    tcbc_newest = &pmc->tcb_cache_a2b;
	    time_newest = tcb_newest->last_data_time;
	} else if (tv_gt(ptcb_client->last_data_time, time_newest)) {
	    /* this is "most recent" */
	    tcb_newest = ptcb_client;
	    tcbc_newest = &pmc->tcb_cache_a2b;
	    time_newest = ptcb_client->last_data_time;
	}
    }

    return(tcbc_newest);
}


static hash
IPHash(
    ipaddr *paddr)
{
    hash hval = 0;
    int i;

    if (ADDR_ISV4(paddr)) { /* V4 */
	hval = paddr->un.ip4.s_addr;
    } else if (ADDR_ISV6(paddr)) { /* V6 */
	for (i=0; i < 16; ++i)
	    hval += paddr->un.ip6.s6_addr[i];
    } else {
	/* address type unknown */
	fprintf(stderr,"Unknown IP address type %d encountered\n",
		ADDR_VERSION(paddr));
	exit(-1);
    }

    return(hval);
}


static hash
EndpointHash(
    tcp_pair_addrblock *addr_pair)
{
    hash hval;

    hval =
	IPHash(&addr_pair->a_address) +
	IPHash(&addr_pair->b_address);

    return(hval % ENDPOINT_PAIR_HASHSIZE);
}



static Bool
SameEndpoints(
    tcp_pair_addrblock	*pap1,
    tcp_pair_addrblock	*pap2)
{
    if (IPcmp(&pap1->a_address,&pap2->a_address) == 0) {
	if (IPcmp(&pap1->b_address,&pap2->b_address) == 0) {
	    return(TRUE);
	}
    } else if (IPcmp(&pap1->a_address,&pap2->b_address) == 0) {
	if (IPcmp(&pap1->b_address,&pap2->a_address) == 0) {
	    return(TRUE);
	}
    }

    return(FALSE);
}


/* Data is considered a NEW burst if:
 *  1) There was intervening data in the other direction
 *  2) All previous data was ACKed
 */
static Bool
IsNewBurst(
    module_conninfo *pmc,
    tcb *ptcb,
    seqnum seq)
{
    tcb *ptcb_otherdir = ptcb->ptwin;

    /* check for intervening data */
    if (ptcb == pmc->tcb_lastdata) {
	/* no intervening data */
	return(FALSE);
    }
    pmc->tcb_lastdata = ptcb;

    /* check for old data ACKed */
    if (SEQ_LESSTHAN(ptcb_otherdir->ack,seq)) {
	/* not ACKed */
	return(FALSE);
    }

    /* ... else, it's a new burst */

    return(TRUE);
}

/* is this connection "active" */
/* 1: not reset */
/* 2: either 0 or 1 fins */
static Bool
ActiveConn(
    module_conninfo *pmc)
{
    if (FinCount(pmc->ptp) > 1)
	return(FALSE);

    if (ConnReset(pmc->ptp))
	return(FALSE);
    
    return(TRUE);
}


#endif /* LOAD_MODULE_TCPLIB */
