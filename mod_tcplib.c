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
 * Author:	Eric Helvey
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ehelvey@cs.ohiou.edu
 * Modified:    Shawn Ostermann
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



/* structure to keep track of "inside" */
struct insidenode {
    ipaddr min;
    ipaddr max;
    struct insidenode *next;
} *inside_head = NULL;




/* Local global variables */

/* generic size list */
struct sizes {
    int maxix;
    int arraysize;
    int total_count;
    int *size_list;
};

/* global data */

static struct tcplibstats {
    /* telnet packet sizes */
    struct sizes *telnet_pktsize;

    /* telnet interarrival times */
    struct sizes *telnet_interarrival;

    /* conversation interarrival times */
    struct sizes *conv_interarrival;

    int tcplib_breakdown_total[NUM_APPS];
    int tcplib_breakdown_interval[NUM_APPS];

    /* histogram files */
    FILE* hist_file;

    int interval_count;
    timeval last_converse;
    timeval last_interval;
} *global_pstats[3] = {NULL};
enum t_statsix {LOCAL = 0, INCOMING = 1, OUTGOING = 2};
static char *data_prefixes[3] = {"local","incoming","outgoing"};

static int debug;
static const char breakdown_hash_char[] = { 'S', 'N', 'T', 'F', 'H' };
static int ipport_offset = IPPORT_OFFSET;
static char *current_file = NULL;
static char *output_dir = DEFAULT_TCPLIB_DATADIR;


typedef Bool (*f_testinside) (tcb *);



/* Function Prototypes */
static void ParseArgs(char *argstring);
static int breakdown_type(int port);
static void do_final_breakdown(char* filename, struct tcplibstats *pstats);
static void do_all_final_breakdowns(void);
static void do_tcplib_final_converse(char *filename, struct sizes *psizes);
static void do_tcplib_next_converse(tcb *ptcb);
static Bool is_ftp_control_conn(tcp_pair *ptp);
static Bool is_ftp_data_conn(tcp_pair *ptp);
static Bool is_http_conn(tcp_pair *ptp);
static Bool is_nntp_conn(tcp_pair *ptp);
static Bool is_smtp_conn(tcp_pair *ptp);
static Bool is_telnet_conn(tcp_pair *ptp);
static Bool is_telnet_port(int port);
static char* namedfile(char *localsuffix, char * file);
static void setup_breakdown(void);
static void tcplib_add_telnet_interarrival(tcp_pair *ptp, struct timeval *ptp_saved, struct sizes *psizes);
static void tcplib_add_telnet_packetsize(struct tcplibstats *pstats, int length);
static void tcplib_do_ftp_control_size(char *filename, f_testinside p_tester);
static void tcplib_do_ftp_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_ftp_num_items(void);
static void tcplib_do_http_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_nntp_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_nntp_numitems(void);
static void tcplib_do_smtp_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_telnet_duration(char *filename, f_testinside p_tester);
static void tcplib_do_telnet_interarrival(char *filename, f_testinside p_tester);
static void tcplib_do_telnet_packetsize(char *filename, f_testinside p_tester);
static void tcplib_init_setup(void);
static void update_breakdown(tcp_pair *ptp, struct tcplibstats *pstats);

/* prototypes for determining "insideness" */
static void DefineInside(char *iplist);
static Bool IsInside(ipaddr *pipaddr);
static Bool TestOutgoing(tcb *ptcb);
static Bool TestIncoming(tcb *ptcb);
static Bool TestLocal(tcb *ptcb);
static int InsideBytes(tcp_pair *, f_testinside);

/* various helper routines used by many others -- sdo */
static void tcplib_do_GENERIC_itemsize(
    char *filename, Bool (*f_whichport)(tcp_pair *),
    f_testinside p_tester, int bucketsize);
static struct sizes *AddToSizeArray(struct sizes *psizes, int ix, int val);
static void StoreSizes(char *filename, char *header1, char *header2,
		       int bucketsize, struct sizes *psizes);
static struct sizes *ReadOldFile(char *filename, int bucketsize,
				 int maxlegal, struct sizes *psizes);
static struct sizes *MakeSizes(int nelem);



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

    if (debug>2)
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
    
    if (debug>2)
	printf("DefineInside(%s) called\n", iplist);

    inside_head = DefineInsideRecurse(iplist);

    if (debug) {
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
    if (inside_head == NULL)
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
TestOutgoing(tcb *ptcb)
{
    struct stcp_pair *ptp = ptcb->ptp;

    if (ptcb == &ptp->a2b)
	return(IsInside(&ptp->addr_pair.a_address) &&
	       !IsInside(&ptp->addr_pair.b_address));
    else
	return(IsInside(&ptp->addr_pair.b_address) &&
	       !IsInside(&ptp->addr_pair.a_address));
}

static Bool
TestIncoming(tcb *ptcb)
{
    struct stcp_pair *ptp = ptcb->ptp;

    if (ptcb == &ptp->a2b)
	return(!IsInside(&ptp->addr_pair.a_address) &&
	       IsInside(&ptp->addr_pair.b_address));
    else
	return(!IsInside(&ptp->addr_pair.b_address) &&
	       IsInside(&ptp->addr_pair.a_address));
}


static Bool
TestLocal(tcb *ptcb)
{
    struct stcp_pair *ptp = ptcb->ptp;

    return(IsInside(&ptp->addr_pair.a_address) &&
	   IsInside(&ptp->addr_pair.b_address));
}


static int InsideBytes(
    tcp_pair *ptp,		/* The tcp pair */
    f_testinside p_tester)	/* function to test "insideness" */
{
    int temp = 0;

    /* if "p_tester" likes this side of the connection, count the bytes */
    if ((*p_tester)(&ptp->a2b))
	temp += ptp->a2b.data_bytes;

    /* if "p_tester" likes this side of the connection, count the bytes */
    if ((*p_tester)(&ptp->b2a))
	temp += ptp->b2a.data_bytes;

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
	 * we divide the the data into three sets:
	 * data.incoming:
	 *    for all data flowing from "inside" to "outside"
	 * data.outgoing:
	 *    for all data flowing from "outside" to "inside"
	 * data.local:
	 *    for all data flowing from "inside" to "inside"
	 */
	else
	if (argv[i] && !strncmp(argv[i], "-i", 2)) {
	    DefineInside(argv[i]+2);
	}


	/* local debugging flag */
	else
	if (argv[i] && !strncmp(argv[i], "-d", 2)) {
	    ++debug;
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
RunAllThree(
    void (*f_runme) (char *,f_testinside),
    char *thefile)
{
    char *filename;

    filename = namedfile("local",thefile);
    (*f_runme)(filename,TestLocal);

    if (inside_head == NULL)
	return;  /* none of the rest will match anyway */

    filename = namedfile("incoming",thefile);
    (*f_runme)(filename,TestIncoming);

    filename = namedfile("outgoing",thefile);
    (*f_runme)(filename,TestOutgoing);

}
void tcplib_done()
{
    char *filename;
    
    /* do TELNET */
    RunAllThree(tcplib_do_telnet_packetsize,TCPLIB_TELNET_PACKETSIZE_FILE);
    RunAllThree(tcplib_do_telnet_interarrival,TCPLIB_TELNET_INTERARRIVAL_FILE);
    RunAllThree(tcplib_do_telnet_duration,TCPLIB_TELNET_DURATION_FILE);



    /* do FTP */
    RunAllThree(tcplib_do_ftp_control_size,TCPLIB_FTP_CTRLSIZE_FILE);
    RunAllThree(tcplib_do_ftp_itemsize,TCPLIB_FTP_ITEMSIZE_FILE);
    tcplib_do_ftp_num_items();     /* Not Done */



    /* do SMTP */
    RunAllThree(tcplib_do_smtp_itemsize,TCPLIB_SMTP_ITEMSIZE_FILE);



    /* do NNTP */
    RunAllThree(tcplib_do_nntp_itemsize,TCPLIB_NNTP_ITEMSIZE_FILE);
    tcplib_do_nntp_numitems();	/* Not Done */


    /* do HTTP */
    RunAllThree(tcplib_do_http_itemsize,TCPLIB_HTTP_ITEMSIZE_FILE);


    /* do the breakdown stuff */
    do_all_final_breakdowns();


    /* do the conversation interrival time */
    filename = namedfile("incoming",TCPLIB_NEXT_CONVERSE_FILE);
    do_tcplib_final_converse(filename,
			     global_pstats[INCOMING]->conv_interarrival);
    filename = namedfile("outgoing",TCPLIB_NEXT_CONVERSE_FILE);
    do_tcplib_final_converse(filename,
			     global_pstats[OUTGOING]->conv_interarrival);
    filename = namedfile("local",TCPLIB_NEXT_CONVERSE_FILE);
    do_tcplib_final_converse(filename,
			     global_pstats[LOCAL]->conv_interarrival);

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
			* feels is important.  In this case, we store the time
			* of the last packet in the conversation to arrive. */
    )
{
    struct tcphdr *tcp;  /* TCP header information */
    int data_len = 0;    /* Length of the data cargo in the packet, and
			  * the period of time between the last two packets
			  * in a conversation */
    int a2b_len;         /* The type of traffic associated with a's port # */
    int b2a_len;         /* The type of traffic associated with b's port # */
    tcb *ptcb;
    struct tcplibstats *pstats;
    

    /* Setting a pointer to the beginning of the TCP header */
    tcp = (struct tcphdr *) ((char *)pip + (4 * pip->ip_hl));

    /* see which of the 2 TCB's this goes with */
    if (ptp->addr_pair.a_port == ntohs(tcp->th_dport))
	ptcb = &ptp->a2b;
    else
	ptcb = &ptp->b2a;


    /* see where to keep the stats */
    if (TestLocal(ptcb))
	pstats = global_pstats[LOCAL];
    else if (TestIncoming(ptcb))
	pstats = global_pstats[INCOMING];
    else if (TestOutgoing(ptcb))
	pstats = global_pstats[OUTGOING];
    else {
	/* external? */
	static int warned = FALSE;
	if (!warned) {
	    warned = TRUE;
	    fprintf(stderr,"
\n\nWarning: I'm seeing 'external' traffic according to the definition\n\
of 'inside' that you provided, that might be bad...\n\n");
	}
	return;
    }


    /* Let's do the telnet packet sizes.  Telnet packets are the only
     * ones where we actually care about the sizes of individual packets.
     * All the other connection types are a "send as fast as possible" 
     * kind of setup where the packet sizes are always optimal.  Because
     * of this, we need the size of each and every telnet packet that 
     * comes our way. */
    if (is_telnet_conn(ptp)) {
	data_len = pip->ip_len - 
	    (4 * pip->ip_hl) -	/* less the IP header */
	    (4 * tcp->th_off);	/* less the TCP header */

	tcplib_add_telnet_packetsize(pstats,data_len);
    }


    /* Here's where we'd need to do telnet interarrival times.  The
     * same basic scenario applies with telnet packet interarrival
     * times.  Because telnet type traffic is "stop and go", we need
     * to be able to model how long the "stops" are.  So we measure
     * the time in between successive packets in a single telnet
     * conversation. */
    if (is_telnet_conn(ptp)) {
	tcplib_add_telnet_interarrival(
	    ptp, (struct timeval *)pmodstruct,
	    pstats->telnet_interarrival);
    }


    if ((a2b_len = breakdown_type(ptp->addr_pair.a_port)) != -1)
	pstats->tcplib_breakdown_interval[a2b_len] += ptp->a2b.data_bytes;

    if ((b2a_len = breakdown_type(ptp->addr_pair.b_port)) != -1)
	pstats->tcplib_breakdown_interval[b2a_len] += ptp->b2a.data_bytes;

    /* This is just a sanity check to make sure that we've got at least
     * one time, and that our breakdown section is working on the same
     * file that we are. */
    data_len = (ptp->last_time.tv_sec - pstats->last_interval.tv_sec);
    
    if (data_len >= TIMER_VAL) {
	update_breakdown(ptp, pstats);
    }

    return;
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
    tcb *ptcb;
    struct timeval *pmodstruct;   /* Pointer to a timeval structure.  The
				   * timeval structure becomes the time of
				   * the last connection.  The pmodstruct
				   * is tcptrace's way of allowing modules
				   * to keep track of information about
				   * connections */

    /* it's a new connections, the the tcb is for host A */
    ptcb = &ptp->a2b;

    do_tcplib_next_converse(ptcb);

    pmodstruct = MallocZ(sizeof(struct timeval));

    return (void *)pmodstruct;
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


    for (ix = LOCAL; ix <= OUTGOING; ++ix) {
	/* create the big data structure */
	global_pstats[ix] = pstats = MallocZ(sizeof(struct tcplibstats));

	pstats->telnet_pktsize = MakeSizes(0);
	pstats->telnet_interarrival = MakeSizes(0);
	pstats->conv_interarrival = MakeSizes(0);

	for(i = 0; i < NUM_APPS; i++){
	    pstats->tcplib_breakdown_total[i] = 0;
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
    
    for (ix = LOCAL; ix <= OUTGOING; ++ix) {
	struct tcplibstats *pstats = global_pstats[ix];
	char *prefix = data_prefixes[ix];
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

    /* Move the data for this breakdown interval into the total breakdown
     * data area.  We'll be using this stuff at the end, so we need to
     * keep track of it now. */
    for(i = 0; i < NUM_APPS; i++) {
	pstats->tcplib_breakdown_total[i] +=
	    pstats->tcplib_breakdown_interval[i]/1000;
	pstats->tcplib_breakdown_interval[i] = 0;
    }

    /* Update the breakdown interval */
    pstats->interval_count++;

    /* Update the time that the last breakdown interval occurred. */
    pstats->last_interval = ptp->last_time;
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

    if (inside_head != NULL)
	sprintf(directory, "%s_%s", output_dir, localsuffix);
    else
	sprintf(directory, "%s", output_dir);

    /* try to CREATE the directory if it doesn't exist */
    if (access(directory,F_OK) != 0) {
	if (mkdir(directory,0755) != 0) {
	    perror(directory);
	    exit(-1);
	}
	if (debug)
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
    struct tcplibstats *pstats)
{
    int i;            /* Looping variable */
    FILE* fil;        /* File descriptor for the traffic breakdown file */
    long file_pos;    /* Offset within the traffic breakdown file */
    int a2b_len;      /* What kind of port is A's port? */
    int b2a_len;      /* What kind of port is B's port? */
    tcp_pair *ptp;    /* A pointer to a conversation struct */

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
	/* The breakdown file line associated with each trace file is
	 * prefaced with the trace file's name.  This was part of the
	 * original TCPLib format. */
	fprintf(fil, "%s", current_file);

	/* Here, we're both setting up the tpclib_breakdown_totals, and
	 * also removing the breakdown totals from the previous file
	 */
    	for(i = 0; i < NUM_APPS; i++)
	    pstats->tcplib_breakdown_total[i] = 0;

	/* Scan through the entire set of conversations, and pull out
	 * the number of conversations for each traffic type */
	for(i = 0; i < num_tcp_pairs; i++) {
	    ptp = ttp[i];

	    if ((a2b_len = breakdown_type(ptp->addr_pair.a_port)) != -1)
		pstats->tcplib_breakdown_total[a2b_len]++;
	    
	    if ((b2a_len = breakdown_type(ptp->addr_pair.b_port)) != -1)
		pstats->tcplib_breakdown_total[b2a_len]++;
	}

	/* Print out the ratio of conversations of each traffic type
	 * to total number of converstaions observed in the trace file
	 */
	for(i = 0; i < NUM_APPS; i++) {
	    fprintf(fil, "\t%.4f",
		    ((float)pstats->tcplib_breakdown_total[i])/num_tcp_pairs);
	}

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
    
    filename = namedfile("incoming",TCPLIB_BREAKDOWN_FILE);
    do_final_breakdown(filename, global_pstats[INCOMING]);
    filename = namedfile("outgoing",TCPLIB_BREAKDOWN_FILE);
    do_final_breakdown(filename, global_pstats[OUTGOING]);
    filename = namedfile("local",TCPLIB_BREAKDOWN_FILE);
    do_final_breakdown(filename, global_pstats[LOCAL]);
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
    int port)   /* What real port to examine */
{
    /* This was added in order to handle generating statistics from traffic
     * that was created by the traffic generator.  Since the traffic from the
     * the traffic generator is usually sent to non-standard ports, we need
     * be able to pick out that traffic for analysis.  This is where the
     * ipport_offset comes in.  We know what the offset is, so we just 
     * subtract it.  Big Bubba, No Trubba. */
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
	return TCPLIBPORT_TELNET;
	break;

      case IPPORT_FTP_CONTROL:
/*      case IPPORT_FTP_DATA: */
/* We take out FTP data port because the control connections will be the 
 * deciding factors for the FTP connections */
	return TCPLIBPORT_FTP;
	break;

      case IPPORT_SMTP:
	return TCPLIBPORT_SMTP;
	break;

      case IPPORT_NNTP:
	return TCPLIBPORT_NNTP;
	break;

      case IPPORT_HTTP:
	return TCPLIBPORT_HTTP;
	break;
    
      default:
	return TCPLIBPORT_NONE;
    }

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
    tcb *ptcb)    /* This conversation */
{
    struct tcplibstats *pstats;
    int etime;   /* Time difference between the first packet in this
		  * conversation and the first packet in the previous
		  * conversation.  Basically, this is the time between
		  * new conversations. */

    /* see where to keep the stats */
    if (TestLocal(ptcb))
	pstats = global_pstats[LOCAL];
    else if (TestIncoming(ptcb))
	pstats = global_pstats[INCOMING];
    else if (TestOutgoing(ptcb))
	pstats = global_pstats[OUTGOING];
    else {
	/* external? */
	return;
    }

    /* The time 0.0 is what we'll get if this is the first conversation 
     * we've seen in this data file. */
    if (ZERO_TIME(&pstats->last_converse)) {
	/* All we do is store the time for this conversation as the
	 * baseline and go on.  There's really no data here. */
	pstats->last_converse = current_time;
	return;
    }


    /* We want the time difference in milliseconds.  Perhaps this will
     * get changed to microseconds. */
    etime = (int)(elapsed(pstats->last_converse,
			  current_time)/1000.0); /* convert us to ms */

    /* sdo note */
    /* Eric originally was very worried about a huge sparse array to maintain */
    /* these things.  I'm not so worried, so I'll just use the dynamic array stuff */
    /* from above to keep track of it, burning memory but saving time */
    pstats->conv_interarrival =
	AddToSizeArray(pstats->conv_interarrival, etime, 1);

    
    /* Updating the last conversation timer */
    pstats->last_converse = current_time;

    return;
}

/* End of the breakdown section */











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
    struct sizes *psizes)
{
    const int bucketsize = 1;


    /* sdo - OK, pstats->conv_interarrival already has the counts we */
    /* made.  First, include anything from an existing file. */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* Now, dump out the combined data */
    StoreSizes(filename,"Conversation Interval Time (ms)",
	       "% Interarrivals", bucketsize,psizes);
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
    int port)       /* The port we're looking at */
{
    switch(port) {
      case IPPORT_LOGIN:
      case IPPORT_KLOGIN:
      case IPPORT_OLDLOGIN:
      case IPPORT_FLN_SPX:
      case IPPORT_UUCP_LOGIN:
      case IPPORT_KLOGIN2:
      case IPPORT_NLOGIN:
      case IPPORT_TELNET:
	return TRUE;
	break;

      default:
	return FALSE;
    }
}
static Bool
is_telnet_conn(
    tcp_pair *ptp)
{
    tcp_pair_addrblock *paddr = &ptp->addr_pair;

    return(is_telnet_port(paddr->a_port-ipport_offset) ||
	   is_telnet_port(paddr->b_port-ipport_offset));
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
    int i;                   /* Looping variable */
    struct sizes *psizes = NULL;
    const int bucketsize = 100;	/* 100 millisecond buckets */
    

    /* This section reads in the data from the existing telnet duration
     * file in preparation for merging with the current data. */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* Fill the array with the current data */
    for(i = 0; i < num_tcp_pairs; i++) {
	tcp_pair *ptp = ttp[i];

	/* Only work this for telnet connections */
	if (is_telnet_conn(ptp)) {
	    /* convert the time difference to ms */
	    int temp = (int)(elapsed(ptp->first_time,
				     ptp->last_time)/1000.0); /* convert us to ms */


	    /* increment the number of instances at this time. */
	    psizes = AddToSizeArray(psizes,temp/bucketsize, 1);
	}
    }


    /* Output data to the file */
    StoreSizes(filename,"Duration (ms)", "% Conversations",
	       bucketsize,psizes);


    /* free the dynamic memory */
    if (psizes) {
	free(psizes->size_list);
	free(psizes);
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
    struct timeval* ptp_saved,  /* The time of the last packet in the
				   conversation */
    struct sizes *psizes)
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
	/* If this is the first packet we've seen, then all we need
	 * to do is store this tiem in the ptp_saved structure and
	 * throw it back.  We'll be able to get some data the next
	 * time. */
	*ptp_saved = ptp->last_time;

	return;
    }
	
    /* Determining the time difference in ms */
    temp = (int)(elapsed(*ptp_saved, current_time)/1000.0); /* convert us to ms */

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
/*     printf("temp is %d, elapsed was %f\n", temp, elapsed(*ptp_saved, current_time)); */
    (void) AddToSizeArray(psizes, temp, 1);

    /* now we just want to record this time and store it with TCPTrace
     * until we need it - which will be the next time that this 
     * conversation receives a packet. */
    *ptp_saved = ptp->last_time;

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
    const int bucketsize = 1;
    struct sizes *psizes = NULL;

    /* ugly interface conversion :-( */
    if (p_tester == TestIncoming)
	psizes = global_pstats[INCOMING]->telnet_interarrival;
    else if (p_tester == TestOutgoing)
	psizes = global_pstats[OUTGOING]->telnet_interarrival;
    else if (p_tester == TestLocal)
	psizes = global_pstats[LOCAL]->telnet_interarrival;
    else {
	fprintf(stderr,
		"tcplib_do_telnet_interarrival: internal inconsistancy!\n");
	exit(-1);
    }



    /* add in the data from the old run (if it exists) */
    psizes = ReadOldFile(filename, bucketsize, MAX_TEL_INTER_COUNT, psizes);


    /* Dumping the data out to the data file */
    StoreSizes(filename, "Interarrival Time (ms)", "% Interarrivals",
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
    const int bucketsize = 1;
    struct sizes *psizes = NULL;

    /* ugly interface conversion :-( */
    if (p_tester == TestIncoming)
	psizes = global_pstats[INCOMING]->telnet_pktsize;
    else if (p_tester == TestOutgoing)
	psizes = global_pstats[OUTGOING]->telnet_pktsize;
    else if (p_tester == TestLocal)
	psizes = global_pstats[LOCAL]->telnet_pktsize;
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
    StoreSizes(filename, "Packet Size (bytes)", "% Packets",
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
    pstats->telnet_pktsize = AddToSizeArray(pstats->telnet_pktsize,
					    length, 1);
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
Bool is_ftp_data_conn(
    tcp_pair *ptp)		/* connection information */
{
    tcp_pair_addrblock *paddr = &ptp->addr_pair;
    return ((paddr->a_port-ipport_offset == IPPORT_FTP_DATA) ||
	    (paddr->b_port-ipport_offset == IPPORT_FTP_DATA));
}






/***************************************************************************
 * 
 * Function Name: is_ftp_control_conn
 * 
 * Returns: Boolean value
 *
 * Purpose: To determine if the connection is an FTP control port.
 *
 * Called by: tcplib_do_ftp_control_size() in mod_tcplib.c
 * 
 ****************************************************************************/
Bool is_ftp_control_conn(
    tcp_pair *ptp)		/* connection information */
{
    tcp_pair_addrblock *paddr = &ptp->addr_pair;
    return ((paddr->a_port-ipport_offset == IPPORT_FTP_CONTROL) ||
	    (paddr->b_port-ipport_offset == IPPORT_FTP_CONTROL));
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
    const int bucketsize = 5;	/* scale bucket by 5 bytes */

    tcplib_do_GENERIC_itemsize(filename, is_ftp_data_conn,
			       p_tester, bucketsize);
}


void tcplib_do_ftp_num_items(void)
{
    /* Need to figure out how to know when the control connection has
     * spawned off new data connections.
     */
}


static void tcplib_do_ftp_control_size(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 1;

    tcplib_do_GENERIC_itemsize(filename, is_ftp_control_conn,
			       p_tester, bucketsize);
}
/* End of FTP Stuff */




/* Begin SMTP Stuff */
Bool is_smtp_conn(
    tcp_pair *ptp)		/* connection information */
{
    tcp_pair_addrblock *paddr = &ptp->addr_pair;
    return ((paddr->a_port-ipport_offset == IPPORT_SMTP) ||
	    (paddr->b_port-ipport_offset == IPPORT_SMTP));
}

static void tcplib_do_smtp_itemsize(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 5;	/* scale bucket by 5 bytes */

    tcplib_do_GENERIC_itemsize(filename, is_smtp_conn,
			       p_tester, bucketsize);
}
/* Done SMTP Stuff */




/* Begin NNTP Stuff */
Bool is_nntp_conn(
    tcp_pair *ptp)		/* connection information */
{
    tcp_pair_addrblock *paddr = &ptp->addr_pair;
    return ((paddr->a_port-ipport_offset == IPPORT_NNTP) ||
	    (paddr->b_port-ipport_offset == IPPORT_NNTP));
}


static void tcplib_do_nntp_itemsize(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 1024;	/* scale everything by 1024 */

    tcplib_do_GENERIC_itemsize(filename, is_nntp_conn,
			       p_tester, bucketsize);
}


static void
tcplib_do_nntp_numitems(void)
{
    /* Basically we need to figure out how many different
     * articles are bundles up together?  I'm not quite sure
     * how the whole NNTP thing works anyways.
     */
}
/* Done NNTP Stuff */



/* Begin HTTP Stuff */
Bool is_http_conn(
    tcp_pair *ptp)		/* connection information */
{
    tcp_pair_addrblock *paddr = &ptp->addr_pair;
    return ((paddr->a_port-ipport_offset == IPPORT_HTTP) ||
	    (paddr->b_port-ipport_offset == IPPORT_HTTP));
}


static void tcplib_do_http_itemsize(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    const int bucketsize = 10;  /* sdo - changed from Eric */

    tcplib_do_GENERIC_itemsize(filename, is_http_conn,
			       p_tester, bucketsize);
}


/***************************************************************************
 **
 ** Support Routines
 **
 ***************************************************************************/

/* populate the size array, one entry at a time */
static struct sizes *
AddToSizeArray(
    struct sizes *psizes,
    int ix,
    int val)
{
    /* if the array doesn't exist yet, make it some big size */
    if (psizes == NULL) {
	psizes = MakeSizes(ix);
    }

    /* if the array is too small, quadruple it */
    if (ix > psizes->arraysize) {
	int oldarraysize = psizes->arraysize;
	while (ix > psizes->arraysize)
	    psizes->arraysize *= 4;

	/* reallocate the array (REALLY expensive!) */
	psizes->size_list = ReallocZ(psizes->size_list,
				     sizeof(int) * oldarraysize, 
				     sizeof(int) * psizes->arraysize);
    }

    /* OK, finally, all is safe */
    psizes->size_list[ix] += val;
    psizes->total_count += val;
    if (ix > psizes->maxix)
	psizes->maxix = ix;

    /* return the (possibly modified) structure */
    return(psizes);
}


static void
StoreSizes(
    char *filename,
    char *header1,
    char *header2,
    int bucketsize,
    struct sizes *psizes)
{
    FILE *fil;
    int i;
    int running_total = 0;

    if (debug)
	printf("Saving data for file '%s'\n", filename);

    if (!(fil = fopen(filename, "w"))) {
	perror(filename);
	exit(1);
    }

    fprintf(fil, "%s\t%s\tRunning Sum\tCounts\n", header1, header2);

    if (psizes == NULL) {
	if (debug)
	    printf("No data for file '%s'\n", filename);
    } else {
	for(i = 0; i <= psizes->maxix; i++) {
	    int value = i * bucketsize;
	    running_total += psizes->size_list[i];

	    if (psizes->size_list[i]) {
		fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
			(float)value, /* sdo bugfix */
			(((float)running_total)/((float)psizes->total_count)),
			running_total,
			psizes->size_list[i]);
	    }
	}
    }

    fclose(fil);
}


static struct sizes *
ReadOldFile(
    char *filename,
    int bucketsize,
    int maxlegal,		/* upper limit on array IX (or 0) */
    struct sizes *psizes)
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
	    psizes = AddToSizeArray(psizes,
				    (((int)bytes)/bucketsize),
				    count);
	}

	if (debug) {
	    if (psizes && (linesread > 0))
		printf("Read data from old file '%s' (%d values)\n",
		       filename, psizes->total_count);
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
    Bool (*f_whichport)(tcp_pair *),
    f_testinside p_tester,	/* functions to test "insideness" */
    int bucketsize)		/* how much data to group together */
{
    int i;                    /* Looping variables */
    struct sizes *psizes = NULL;


    /* If an old data file exists, open it, read in its contents
     * and store them until they are integrated with the current
     * data */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);


    /* fill out the array with data from the current connections */
    for(i = 0; i < num_tcp_pairs; i++) {
	tcp_pair *ptp = ttp[i];

	/* We only need the stats if it's the right port */
	if ((*f_whichport)(ptp)) {
	    int nbytes = InsideBytes(ptp,p_tester);

	    /* if there's no DATA, don't count it! */
	    if (nbytes != 0)
		psizes = AddToSizeArray(psizes,nbytes/bucketsize, 1);
	}
    }


    /* store all the data (old and new) into the file */
    StoreSizes(filename,"Article Size (bytes)", "% Articles",
	       bucketsize,psizes);


    /* free the dynamic memory */
    if (psizes) {
	free(psizes->size_list);
	free(psizes);
    }
}


static struct sizes *
MakeSizes(
    int nelem)
{
    int default_size = 1024;
    struct sizes *psizes;

    while (nelem >= default_size)
	default_size *= 2;

    psizes = MallocZ(sizeof(struct sizes));
    psizes->arraysize = default_size;
    psizes->size_list = MallocZ(psizes->arraysize*sizeof(int));

    return(psizes);
}



    

#endif /* LOAD_MODULE_TCPLIB */
