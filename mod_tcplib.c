/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *               2002, 2003, 2004
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
 * Original Author: Eric Helvey
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ehelvey@cs.ohiou.edu
 *		http://www.tcptrace.org/
 * Extensively Modified:    Shawn Ostermann
 */
#include "tcptrace.h"
static char const GCC_UNUSED rcsid[] =
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
#include "mod_tcplib.h"
#include "dyncounter.h"


/* reading old files is problematic and I never use it anyway!!!
   it probably doesn't work anymore.
   sdo - Thu Aug  5, 1999 */
#undef READ_OLD_FILES

/* we're no longer interested in the old phone/conv columns */
#undef INCLUDE_PHONE_CONV

/* Local global variables */

/* different types of "directions" */
#define NUM_DIRECTION_TYPES 4
enum t_dtype {LOCAL = 0, INCOMING = 1, OUTGOING = 2, REMOTE = 3};
static char *dtype_names[NUM_DIRECTION_TYPES] = {"local","incoming","outgoing", "remote"};

/* structure to keep track of "inside" */
struct insidenode {
    ipaddr min;
    ipaddr max;
    struct insidenode *next;
} *inside_head = NULL;
#define LOCAL_ONLY (inside_head == NULL)



/* for the parallelism hack */
#define BURST_KEY_MAGIC 0x49524720 /* 'I' 'R' 'G' '<space>' */
struct burstkey {
    unsigned long magic;	/* MUST be BURST_KEY_MAGIC */
    unsigned long nbytes;	/* bytes in burst (INCLUDING this struct) */
    unsigned char key;		/* one character key to return */
    unsigned char unused[3];	/* (explicit padding) */
    unsigned long groupnum;	/* for keeping track of parallel HTTP */
};



#ifdef BROKEN
char *BREAKDOWN_APPS_NAMES[] = {
    "app 1",
    "app 2",
    "app 3",
    "app 4",
    "app 5",
    "app 6",
    "app 7",
    "app 8"
};
#endif /* BROKEN */


/* for VM efficiency, we pull the info that we want out of the tcptrace
   structures into THIS structure (or large files thrash) */
typedef struct module_conninfo_tcb {
    /* cached connection type (incoming, remote, etc) */
    enum t_dtype dtype;

    /* cached data bytes */
    u_llong	data_bytes;

    /*
     * FTP: number of data connections against this control conn
     * HTTP:
     * NNTP: number of bursts
     * HTTP: number of bursts
     */
    u_long numitems;

    /* burst info */
    u_long	burst_bytes;	/* size of the current burst */
    struct burstdata *pburst;

    /* was the last segment PUSHed? */
    Bool last_seg_pushed;	/* Thu Aug 26, 1999 - not used  */

    /* last time new data was sent */
    timeval	last_data_time;

    /* link back to REAL information */
    tcb 	*ptcb;

    /* previous connection of same type */
    struct module_conninfo *prev_dtype_all;/* for ALL app types */
    struct module_conninfo *prev_dtype_byapp; /* just for THIS app type */
} module_conninfo_tcb;


/* structure that this module keeps for each connection */
#define TCB_CACHE_A2B 0
#define TCB_CACHE_B2A 1
#define LOOP_OVER_BOTH_TCBS(var) var=TCB_CACHE_A2B; var<=TCB_CACHE_B2A; ++var
typedef struct module_conninfo {
    /* cached info */
    struct module_conninfo_tcb tcb_cache[2];

    /* this connection should be ignored for breakdown/convarrival */
    Bool ignore_conn;

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

    /* for parallel http sessions */
    struct parallelism *pparallelism;

    /* unidirectional conns ignored totally */
    Bool unidirectional_http;

    /* for determining bursts */
    tcb *tcb_lastdata;

    /* to determine parallelism in conns, trafgen encodes a group
       number in the data */
    u_long http_groupnum;
    
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


/* for tracking burst data */
struct burstdata {
    dyn_counter nitems;		/* total items (bursts) in connection */
    dyn_counter size;		/* size of the items */
    dyn_counter idletime;	/* idle time between bursts */
};

/* for tracking number of connections */
struct parallelism {
    Bool	counted[NUM_DIRECTION_TYPES];
    				/* have we already accumulated this? */
				/* (in each of the 4 directions) */
    Bool	persistant[2];	/* is this persistant (for each TCB) */
    u_short	maxparallel;	/* maximum degree of parallelism */
    u_long	ttlitems[2];	/* across entire group (each dir) */
};



static struct tcplibstats {
    /* telnet packet sizes */
    dyn_counter telnet_pktsize;

    /* telnet interarrival times */
    dyn_counter telnet_interarrival;

    /* conversation interarrival times */
    dyn_counter conv_interarrival_all;

    /* protocol-specific interarrival times */
    dyn_counter conv_interarrival_byapp[NUM_APPS];

    /* conversation duration */
    dyn_counter conv_duration;

    /* for the interval breakdowns */
    int interval_count;
    timeval last_interval;
    int tcplib_breakdown_interval[NUM_APPS];

    /* histogram files */
    MFILE *hist_file;

    /* for NNTP, we track: */
    /* # items per connection */
    /* idletime between items */
    /* burst size */
    struct burstdata nntp_bursts;


    /* for HTTP1.0, we track: */
    /* # items per connection */
    /* # connections */
    /* idletime between items */
    /* burst size */
    struct burstdata http_P_bursts;
    dyn_counter http_P_maxconns; /* max degree of concurrency */
    dyn_counter http_P_ttlitems; /* ttl items across whole parallel group */
    dyn_counter http_P_persistant; /* which parallel groups are persistant */

    /* for HTTP1.1, we track: */
    /* # items per connection */
    /* idletime between items */
    /* burst size */
    struct burstdata http_S_bursts;

    /* telnet packet sizes */
    dyn_counter throughput;
    int throughput_bytes;
} *global_pstats[NUM_DIRECTION_TYPES] = {NULL};


/* local debugging flag */
static int ldebug = 0;

/* parallelism for our TRAFGEN files */
static Bool trafgen_generated = FALSE;

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

/* HTTP endpoints hash table */
endpoint_pair *http_endpoints[ENDPOINT_PAIR_HASHSIZE];


/* internal types */
typedef Bool (*f_testinside) (module_conninfo *pmc,
			      module_conninfo_tcb *ptcbc);

/* various statistics and counters */
static u_long debug_newconn_counter;	/* total conns */
static u_long debug_newconn_badport;	/* a port we don't want */
static u_long debug_newconn_goodport;	/* we want the port */
static u_long debug_newconn_ftp_data_heuristic; /* merely ASSUMED to be ftp data */
static u_llong debug_total_bytes; /* total "bytes" accepted */

/* parallel http counters */
static u_long debug_http_total; /* all HTTP conns */
static u_long debug_http_parallel; /* parallel HTTP, not counted in breakdown/conv */
static u_long debug_http_single;
static u_long debug_http_groups;
static u_long debug_http_slaves;
static u_long debug_http_uni_conns; /* data in at most one direction, ignored */
static u_llong debug_http_uni_bytes; /* data in at most one direction, ignored */
static u_long debug_http_persistant;
static u_long debug_http_nonpersistant;
/* conns by type */
static u_long conntype_counter[NUM_DIRECTION_TYPES];
/* both flows have data */
static u_long conntype_duplex_counter[NUM_DIRECTION_TYPES];
/* this flow has data, twin is empty */
static u_long conntype_uni_counter[NUM_DIRECTION_TYPES];
/* this flow has NO data, twin is NOT empty */
static u_long conntype_nodata_counter[NUM_DIRECTION_TYPES];
/* neither this flow OR its twin has data */
static u_long conntype_noplex_counter[NUM_DIRECTION_TYPES];



/* Function Prototypes */
static void ParseArgs(char *argstring);
static int breakdown_type(tcp_pair *ptp);
static void do_final_breakdown(char* filename, f_testinside p_tester,
			       struct tcplibstats *pstats);
static void do_all_final_breakdowns(void);
static void do_all_conv_arrivals(void);
static void do_tcplib_final_converse(char *filename,
				     char *protocol, dyn_counter psizes);
static void do_tcplib_next_converse(module_conninfo_tcb *ptcbc,
				    module_conninfo *pmc);
static void do_tcplib_conv_duration(char *filename,
				    dyn_counter psizes);
static void do_tcplib_next_duration(module_conninfo_tcb *ptcbc,
				    module_conninfo *pmc);
static void tcplib_cleanup_bursts(void);
static void tcplib_save_bursts(void);
static Bool is_parallel_http(module_conninfo *pmc_new);
static void tcplib_filter_http_uni(void);

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
static void tcplib_do_smtp_itemsize(char *filename, f_testinside p_tester);
static void tcplib_do_telnet_duration(char *filename, f_testinside p_tester);
static void tcplib_do_telnet_interarrival(char *filename,
					  f_testinside p_tester);
static void tcplib_do_telnet_packetsize(char *filename,
					f_testinside p_tester);
static void tcplib_init_setup(void);
static void update_breakdown(tcp_pair *ptp, struct tcplibstats *pstats);
module_conninfo *FindPrevConnection(module_conninfo *pmc,
				    enum t_dtype dtype, int app_type);
static char *FormatBrief(tcp_pair *ptp,tcb *ptcb);
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
static enum t_dtype traffic_type(module_conninfo *pmc,
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
static Bool IsNewBurst(module_conninfo *pmc, tcb *ptcb,
		       module_conninfo_tcb *ptcbc,
		       struct tcphdr *tcp);


/* various helper routines used by many others -- sdo */
static Bool ActiveConn(module_conninfo *pmc);
static Bool RecentlyActiveConn(module_conninfo *pmc);
static void tcplib_do_GENERIC_itemsize(
    char *filename, int btype,
    f_testinside p_tester, int bucketsize);
static void tcplib_do_GENERIC_burstsize(
    char *filename, dyn_counter counter);
static void tcplib_do_GENERIC_P_maxconns(
    char *filename, dyn_counter counter);
static void tcplib_do_GENERIC_nitems(
    char *filename, dyn_counter counter);
static void tcplib_do_GENERIC_idletime(
    char *filename, dyn_counter counter);
static void StoreCounters(char *filename, char *header1, char *header2,
			  int bucketsize, dyn_counter psizes);
#ifdef READ_OLD_FILES
static dyn_counter ReadOldFile(char *filename, int bucketsize,
				 int maxlegal, dyn_counter psizes);
#endif /* READ_OLD_FILES */



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
    char *paddr1;
    char *paddr2;

    if (ldebug>2)
	printf("DefineInsideRange('%s') called\n", ip_pair);

    pdash = strchr(ip_pair,'-');
    if (pdash == NULL) {
	/* just one address, treat it as a range */
	paddr1 = ip_pair;
	paddr2 = ip_pair;
    } else {
	/* a pair */
	*pdash = '\00';
	paddr1 = ip_pair;
	paddr2 = pdash+1;
    }


    pnode = MallocZ(sizeof(struct insidenode));

    paddr = str2ipaddr(paddr1);
    if (paddr == NULL) {
	fprintf(stderr,"invalid IP address: '%s'\n", paddr1);
	exit(-1);
    }
    pnode->min = *paddr;


    paddr = str2ipaddr(paddr2);
    if (paddr == NULL) {
	fprintf(stderr,"invalid IP address: '%s'\n", paddr2);
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
    if (ptcbc == &pmc->tcb_cache[TCB_CACHE_A2B])
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
    if (ptcbc == &pmc->tcb_cache[TCB_CACHE_A2B])
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
    int dir;

    for (LOOP_OVER_BOTH_TCBS(dir)) {
	/* if "p_tester" likes this side of the connection, count the bytes */
	if ((*p_tester)(pmc, &pmc->tcb_cache[dir]))
	    temp += pmc->tcb_cache[dir].data_bytes;
    }

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


	/* parallelism hack */
	else
	if (argv[i] && !strncmp(argv[i], "-H", 2)) {
	    trafgen_generated = TRUE;
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

static void
tcplib_save_bursts()
{
    int dtype;
    module_conninfo *pmc;
    int non_parallel = 0;
    char *filename;

    tcplib_cleanup_bursts();
    

    /* accumulate parallelism stats */
    for (dtype=0; dtype < NUM_DIRECTION_TYPES; ++dtype) {
	non_parallel = 0;
	for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	    struct parallelism *pp = pmc->pparallelism;
	    int dir;

	    /* make sure it's http */
	    if (!is_http_conn(pmc))
		continue;

	    /* ignore unidirectional */
	    if (pmc->unidirectional_http)
		continue;

	    /* check each TCB */
	    for (LOOP_OVER_BOTH_TCBS(dir)) {
		module_conninfo_tcb *ptcbc = &pmc->tcb_cache[dir];

		/* make sure it's
		    -- the right direction
		    -- and parallel
		    -- not already counted */
		if (ptcbc->dtype != dtype)
		    continue;

		if (pp == NULL) {
		    ++non_parallel;
		    continue;
		    }

		if (pp->counted[dtype])
		    continue;

		/* count the max connections */
		AddToCounter(&global_pstats[dtype]->http_P_maxconns,
			     pp->maxparallel, 1, 1);

		/* count the ttl items in the parallel group */
		AddToCounter(&global_pstats[dtype]->http_P_ttlitems,
			     pp->ttlitems[dir],
			     1, GRAN_NUMITEMS);

		/* binary counter, one sample of either: */
		/*  1: NOT persistant */
		/*  2: persistant */
		AddToCounter(&global_pstats[dtype]->http_P_persistant,
			     pp->persistant[dir]?2:1,
			     1, 1);

		/* debugging */
		if (pp->persistant[dir])
		    ++debug_http_persistant;
		else
		    ++debug_http_nonpersistant;

		/* don't count it again! */
		pmc->pparallelism->counted[dtype] = TRUE;
	    }
	}

	/* add the NON-parallel HTTP to the counter */
	AddToCounter(&global_pstats[dtype]->http_P_maxconns, 1,
		     non_parallel, 1);
    }


    /* write all the counters */
    for (dtype=0; dtype < NUM_DIRECTION_TYPES; ++dtype) {
	if (ldebug>1)
	    printf("tcplib: running burstsizes (%s)\n", dtype_names[dtype]);

	/* ---------------------*/
	/*   Burstsize		*/
	/* ---------------------*/
	/* HTTP 1.0 */
	filename = namedfile(dtype_names[dtype],TCPLIB_HTTP_P_BURSTSIZE_FILE);
	tcplib_do_GENERIC_burstsize(filename,
				    global_pstats[dtype]->http_P_bursts.size);

	/* HTTP 1.1 */
	filename = namedfile(dtype_names[dtype],TCPLIB_HTTP_S_BURSTSIZE_FILE);
	tcplib_do_GENERIC_burstsize(filename,
				    global_pstats[dtype]->http_S_bursts.size);

	/* NNTP */
	filename = namedfile(dtype_names[dtype],TCPLIB_NNTP_BURSTSIZE_FILE);
	tcplib_do_GENERIC_burstsize(filename,
				    global_pstats[dtype]->nntp_bursts.size);

	/* ---------------------*/
	/*   Total parallel items */
	/* ---------------------*/
	/* HTTP 1.0 */
	filename = namedfile(dtype_names[dtype],TCPLIB_HTTP_P_TTLITEMS_FILE);
	tcplib_do_GENERIC_nitems(filename,
				 global_pstats[dtype]->http_P_ttlitems);

	/* ---------------------*/
	/*   Num Items in Burst */
	/* ---------------------*/
	/* HTTP 1.1 */
	filename = namedfile(dtype_names[dtype],TCPLIB_HTTP_S_NITEMS_FILE);
	tcplib_do_GENERIC_nitems(filename,
				 global_pstats[dtype]->http_S_bursts.nitems);

	/* NNTP */
	filename = namedfile(dtype_names[dtype],TCPLIB_NNTP_NITEMS_FILE);
	tcplib_do_GENERIC_nitems(filename,
				 global_pstats[dtype]->nntp_bursts.nitems);

	/* ---------------------*/
	/*   Idletime		*/
	/* ---------------------*/

	/* HTTP 1.0 */
	filename = namedfile(dtype_names[dtype],TCPLIB_HTTP_P_IDLETIME_FILE);
	tcplib_do_GENERIC_idletime(filename,
				   global_pstats[dtype]->http_P_bursts.idletime);

	/* HTTP 1.1 */
	filename = namedfile(dtype_names[dtype],TCPLIB_HTTP_S_IDLETIME_FILE);
	tcplib_do_GENERIC_idletime(filename,
				   global_pstats[dtype]->http_S_bursts.idletime);

	/* NNTP */
	filename = namedfile(dtype_names[dtype],TCPLIB_NNTP_IDLETIME_FILE);
	tcplib_do_GENERIC_idletime(filename,
				   global_pstats[dtype]->nntp_bursts.idletime);

	/* store the counters */
	filename = namedfile(dtype_names[dtype],TCPLIB_HTTP_P_MAXCONNS_FILE);
	tcplib_do_GENERIC_P_maxconns(filename,
				     global_pstats[dtype]->http_P_maxconns);
	
	/* store the persistance */
	filename = namedfile(dtype_names[dtype],TCPLIB_HTTP_P_PERSIST_FILE);
	tcplib_do_GENERIC_nitems(filename,
				 global_pstats[dtype]->http_P_persistant);
	

	if (LOCAL_ONLY)
	    break;
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


    /* do HTTP */
    if (ldebug)
	printf("tcplib: running http\n");

    /* filter out the unidirectional HTTP (server pushes) */
    tcplib_filter_http_uni();


    /* for efficiency, do all burst size stuff together */
    if (ldebug)
	printf("tcplib: running burstsizes\n");
    tcplib_save_bursts();


    /* do the breakdown stuff */
    if (ldebug)
	printf("tcplib: running breakdowns\n");
    do_all_final_breakdowns();


    /* do the conversation interrival time */
    if (ldebug)
	printf("tcplib: running conversation interarrival times\n");
    do_all_conv_arrivals();
    for (i=0; i < NUM_DIRECTION_TYPES; ++i) {
	if (ldebug>1)
	    printf("tcplib: running conversation arrivals (%s)\n",
		   dtype_names[i]);
	filename = namedfile(dtype_names[i],TCPLIB_NEXT_CONVERSE_FILE);
	do_tcplib_final_converse(filename, "total",
				 global_pstats[i]->conv_interarrival_all);

#ifdef BROKEN
	/* do the application-specific tables for Mark */
	for (j=0; j < NUM_APPS; ++j) {
	    char new_filename[128];
	    char *app_name = BREAKDOWN_APPS_NAMES[j];
	    snprintf(new_filename,sizeof(new_filename),"%s_%s", filename, app_name);
	    
	    do_tcplib_final_converse(new_filename, app_name,
				     global_pstats[i]->conv_interarrival_byapp[j]);
	}
#endif /* BROKEN */

	/* do conversation durations */
	filename = namedfile(dtype_names[i],TCPLIB_CONV_DURATION_FILE);
	do_tcplib_conv_duration(filename,
				global_pstats[i]->conv_duration);

	if (LOCAL_ONLY)
	    break;
    }

    /* print stats */
    debug_http_single = debug_http_total - debug_http_parallel;
    printf("tcplib: total connections seen: %lu (%lu accepted, %lu bad port)\n",
	   debug_newconn_counter, debug_newconn_goodport, debug_newconn_badport);
    printf("tcplib: total bytes seen: %" FS_ULL "\n",
	   debug_total_bytes);
    printf("tcplib: %lu random connections accepted under FTP data heuristic\n",
	   debug_newconn_ftp_data_heuristic);
    printf("tcplib: %lu HTTP conns (%lu parallel, %lu single)\n",
	   debug_http_total,
	   debug_http_parallel,
	   debug_http_single);
    printf("tcplib: %lu HTTP conns (%lu single, %lu leaders, %lu slaves)\n",
	   debug_http_total,
	   debug_http_single,
	   debug_http_groups,
	   debug_http_slaves);
    printf("tcplib: %lu groups (%lu persistant ||, %lu nonpersistant ||)\n",
	   debug_http_groups,
	   debug_http_persistant,
	   debug_http_nonpersistant);
    printf("tcplib: %lu (%.2f%%) unidir. HTTP conns (%" FS_ULL " bytes, %.2f%%) ignored\n",
	   debug_http_uni_conns,
	   100.0 * ((float)debug_http_uni_conns /
		    (float)(debug_newconn_counter + debug_http_uni_conns)),
	   debug_http_uni_bytes,
	   100.0 * ((float)debug_http_uni_bytes /
		    (float)(debug_total_bytes + debug_http_uni_bytes)));
	   
    for (i=0; i < NUM_DIRECTION_TYPES; ++i) {
	printf("  Flows of type %-8s %5lu (%lu duplex, %lu noplex, %lu unidir, %lu nodata)\n",
	       dtype_names[i],
	       conntype_counter[i],
	       conntype_duplex_counter[i],
	       conntype_noplex_counter[i],
	       conntype_uni_counter[i],
	       conntype_nodata_counter[i]);
    }

    /* dump HTTP groups for debugging */
    {
	module_conninfo *pmc;
	printf("Group Numbers for HTTP conns\n");
	for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	    tcb *ptcb = pmc->tcb_cache[TCB_CACHE_A2B].ptcb;

	    if (pmc->btype != TCPLIBPORT_HTTP)
		continue;
	    
	    if (pmc->unidirectional_http)
		continue;

	    printf("%s: %30s\tGROUPNUM %5lu\tdata %" FS_ULL ":%" FS_ULL "\n",
		   ts2ascii(&ptcb->ptp->first_time),
		   FormatBrief(ptcb->ptp, ptcb),
		   pmc->http_groupnum,
		   pmc->tcb_cache[0].data_bytes,
		   pmc->tcb_cache[1].data_bytes);
	}

	printf("Unidirectional HTTP conns (ignored)\n");
	for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	    tcb *ptcb = pmc->tcb_cache[TCB_CACHE_A2B].ptcb;

	    if (pmc->btype != TCPLIBPORT_HTTP)
		continue;
	    
	    if (!pmc->unidirectional_http)
		continue;
		
		printf("%s: %30s\tGROUPNUM %5lu\tdata %" FS_ULL ":%" FS_ULL "\n",
		   ts2ascii(&ptcb->ptp->first_time),
		   FormatBrief(ptcb->ptp, ptcb),
		   pmc->http_groupnum,
		   pmc->tcb_cache[0].data_bytes,
		   pmc->tcb_cache[1].data_bytes);
	}
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
    enum t_dtype dtype;
    int dir;

    /* first, discard any connections that we aren't interested in. */
    /* That means that pmodstruct is NULL */
    if (pmc == NULL) {
	return;
    }


    /* Setting a pointer to the beginning of the TCP header */
    tcp = (struct tcphdr *) ((char *)pip + (4 * IP_HL(pip)));

    /* calculate the amount of user data */
    data_len = pip->ip_len -	/* size of entire IP packet (and IP header) */
	(4 * IP_HL(pip)) -	/* less the IP header */
	(4 * TH_OFF(tcp));	/* less the TCP header */

    /* stats */
    debug_total_bytes += data_len;

    /* see which of the 2 TCB's this goes with */
    if (ptp->addr_pair.a_port == ntohs(tcp->th_sport)) {
	ptcb = &ptp->a2b;
	dir = TCB_CACHE_A2B;
    } else {
	ptcb = &ptp->b2a;
	dir = TCB_CACHE_B2A;
    }
    ptcbc = &pmc->tcb_cache[dir];


    /* see where to keep the stats */
    dtype = traffic_type(pmc,ptcbc);
    pstats = global_pstats[dtype];

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
		       data_len, dtype_names[dtype]);
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


    /* keep track of bytes/second too */
    if (data_len > 0) {
	static timeval last_time = {0,0};
	unsigned etime;

	/* accumulate total bytes */
	pstats->throughput_bytes += data_len;

	/* elapsed time in milliseconds */
	etime = (int)(elapsed(last_time, current_time)/1000.0);

	/* every 15 seconds, gather throughput stats */
	if (etime > 15000) {
	    AddToCounter(&pstats->throughput,
			 pstats->throughput_bytes, etime, 1024);
	    pstats->throughput_bytes = 0;
	    last_time = current_time;
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

    /* if it's http and we don't already know that it's
       parallel, and this is the first data, and we're
       looking at trafgen data, check the group number encoded
       in the data stream */
    if (is_http_conn(pmc) &&
	trafgen_generated &&
	(ptcb->data_bytes == data_len) &&
	data_len >= sizeof(struct burstkey)) {
	u_char *pdata = (u_char *)tcp + TH_OFF(tcp)*4;
	int available =  (char *)plast - (char *)pdata + 1;
	struct burstkey *pburst;

	if (0)
	    printf("Looking for burst key (in %d bytes of data, %d bytes available)\n",
		   data_len, available);

	/* see where the burst key should be */
	pburst = (void *) pdata;

	if (pburst->magic == BURST_KEY_MAGIC) {
	    pmc->http_groupnum = ntohl(pburst->groupnum);
	    if (ldebug>1)
		printf("FOUND BURST KEY in %s, group num is %lu!\n",
		       FormatBrief(ptcb->ptp, ptcb),
		       pmc->http_groupnum);

	    /* check for parallelism */
	    if (is_parallel_http(pmc)) {
		pmc->ignore_conn = TRUE;
	    }
	}
    }


    /* DATA Burst checking (NNTP and HTTP only) */
    if ((data_len > 0) &&
	(is_nntp_conn(pmc) || is_http_conn(pmc))) {


	/* see if it's a new burst */
	if (IsNewBurst(pmc, ptcb, ptcbc, tcp)) {
	    int etime;

	    if (ldebug > 1)
		printf("New burst starts at time %s for %s\n",
		       ts2ascii(&current_time),
		       FormatBrief(pmc->ptp,ptcb));


	    /* count the PREVIOUS burst item */
	    /* NB: the last is counted in tcplib_cleanup_bursts() */
	    ++ptcbc->numitems;

	    /* special burst handling for HTTP */
	    if (is_http_conn(pmc) && pmc->pparallelism) {
		struct parallelism *pp = pmc->pparallelism;

		if (ptcbc->numitems > 1) {
		    pp->persistant[dir] = TRUE;
		}

		/* add to total bursts in parallel group */
		++pp->ttlitems[dir];
	    }

	    /* accumulate burst size stats */
	    if (ldebug>1)
		printf("Adding burst size %ld to %s\n",
		       ptcbc->burst_bytes,
		       FormatBrief(pmc->ptp,ptcb));
	    AddToCounter(&ptcbc->pburst->size,
			 ptcbc->burst_bytes,
			 1, GRAN_BURSTSIZE);

	    /* reset counter for next burst */
	    ptcbc->burst_bytes = 0;

	    /* determine idle time (elapsed time in milliseconds) */
	    etime = (int)(elapsed(ptcbc->last_data_time,
				  current_time)/1000.0);

	    /* accumulate idletime stats */

	    /* version 2.0 - Thu Aug 26, 1999, subtract the RTT */
	    /* use rtt_last, RTT of last "good ack" */
	    if (ptcb->rtt_last > 0.0) {
		int last_good_rtt = ptcb->rtt_last / 1000.0;
#ifdef OLD
		printf("last_good: %d (%f), etime_0: %d  etime_1: %d\n",
		       last_good_rtt, ptcb->rtt_last, etime, etime-last_good_rtt);
#endif /* OLD */
		etime -= last_good_rtt;

		if (etime >= 0)
		    AddToCounter(&ptcbc->pburst->idletime,
				 etime, 1, GRAN_BURSTIDLETIME);
	    }
	}

	/* accumulate size of current burst */
	ptcbc->burst_bytes += data_len;

	/* remember when the last data was sent (for idletime) */
	ptcbc->last_data_time = current_time;
    }

    /* This is just a sanity check to make sure that we've got at least
     * one time, and that our breakdown section is working on the same
     * file that we are. */
    data_len = (current_time.tv_sec - pstats->last_interval.tv_sec);
    
    if (data_len >= TIMER_VAL) {
	update_breakdown(ptp, pstats);
    }

    /* analysis done, remember the last packet and PUSH status */
    pmc->last_time = current_time;
    ptcbc->last_seg_pushed = PUSH_SET(tcp);

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
    enum t_dtype dtype;
    int dir;

    /* fill the cache */
    for (pmc = module_conninfo_tail; pmc ; pmc=pmc->prev) {
	tcp_pair *ptp = pmc->ptp;	/* shorthand */
	int a2b_bytes = ptp->a2b.data_bytes;
	int b2a_bytes = ptp->b2a.data_bytes;

	/* both sides byte counters */
	pmc->tcb_cache[TCB_CACHE_A2B].data_bytes = a2b_bytes;
	pmc->tcb_cache[TCB_CACHE_B2A].data_bytes = b2a_bytes;

	/* debugging stats */
	if ((a2b_bytes == 0) && (b2a_bytes == 0)) {
	    /* no bytes at all */
	    ++conntype_noplex_counter[pmc->tcb_cache[TCB_CACHE_A2B].dtype];
	    ++conntype_noplex_counter[pmc->tcb_cache[TCB_CACHE_B2A].dtype];
	} else if ((a2b_bytes != 0) && (b2a_bytes == 0)) {
	    /* only A2B has bytes */
	    ++conntype_uni_counter[pmc->tcb_cache[TCB_CACHE_A2B].dtype];
	    ++conntype_nodata_counter[pmc->tcb_cache[TCB_CACHE_B2A].dtype];
	} else if ((a2b_bytes == 0) && (b2a_bytes != 0)) {
	    /* only B2A has bytes */
	    ++conntype_nodata_counter[pmc->tcb_cache[TCB_CACHE_A2B].dtype];
	    ++conntype_uni_counter[pmc->tcb_cache[TCB_CACHE_B2A].dtype];
	} else {
	    /* both sides have bytes */
	    ++conntype_duplex_counter[pmc->tcb_cache[TCB_CACHE_A2B].dtype];
	    ++conntype_duplex_counter[pmc->tcb_cache[TCB_CACHE_B2A].dtype];
	}

	    
	/* globals */
	pmc->last_time = ptp->last_time;
    }


    for (dtype = LOCAL; dtype <= REMOTE; ++dtype) {
	/* do the A sides, then the B sides */
	for (LOOP_OVER_BOTH_TCBS(dir)) {
	    int app;
	    if (ldebug>1)
		printf("  Making previous for %s, side %s\n",
		       dtype_names[dir], (dir==TCB_CACHE_A2B)?"A":"B");

	    /* do conversation interravial calculations by app */
	    for (app=-1; app <= NUM_APPS; ++app) {
		/* note: app==-1 means ALL apps */
		for (pmc = module_conninfo_tail; pmc ; ) {
		    module_conninfo_tcb *ptcbc = &pmc->tcb_cache[dir];

		    /* if app != -1, we just want SOME of them */
		    if ((app != -1) && (pmc->btype != app)) {
			/* don't want this one, try the next one */
			pmc = pmc->prev;
			continue;
		    }

		    if (ptcbc->dtype == dtype) {
			module_conninfo *prev
			    = FindPrevConnection(pmc,dtype,app);
			if (app == -1)
			    ptcbc->prev_dtype_all = prev;
			else
			    ptcbc->prev_dtype_byapp = prev;
			pmc = prev;
		    } else {
			pmc = pmc->prev;
		    }
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

    /* trafgen only uses a few ports... */
    if (trafgen_generated) {
	u_short server_port = ptp->addr_pair.b_port;

	if ((server_port < ipport_offset+IPPORT_FTP_DATA) ||
	    (server_port > ipport_offset+IPPORT_NNTP)) {
	    ++debug_newconn_badport;
	    return(NULL);
	}
    }

    /* verify that it's a connection we're interested in! */
    ++debug_newconn_counter;
    btype = breakdown_type(ptp);
    if (btype == TCPLIBPORT_NONE) {
	++debug_newconn_badport;
	return(NULL); /* so we won't get it back in tcplib_read() */
    } else {
	/* else, it's acceptable, count it */
	++debug_newconn_goodport;
    }

    /* create the connection-specific data structure */
    pmc = NewModuleConn();
    pmc->first_time = current_time;
    pmc->ptp = ptp;
    pmc->tcb_cache[TCB_CACHE_A2B].ptcb = &ptp->a2b;
    pmc->tcb_cache[TCB_CACHE_B2A].ptcb = &ptp->b2a;

    /* cache the address info */
    pmc->addr_pair = ptp->addr_pair;

    /* determine its "insideness" */
    pmc->tcb_cache[TCB_CACHE_A2B].dtype = traffic_type(pmc, &pmc->tcb_cache[TCB_CACHE_A2B]);
    pmc->tcb_cache[TCB_CACHE_B2A].dtype = traffic_type(pmc, &pmc->tcb_cache[TCB_CACHE_B2A]);
    ++conntype_counter[pmc->tcb_cache[TCB_CACHE_A2B].dtype];
    ++conntype_counter[pmc->tcb_cache[TCB_CACHE_B2A].dtype];

    /* determine the breakdown type */
    pmc->btype = btype;

    /* chain it in */
    pmc->prev = module_conninfo_tail;
    module_conninfo_tail = pmc;

    /* setup the burst counter shorthand */
    if ((btype == TCPLIBPORT_NNTP) ||
	(btype == TCPLIBPORT_HTTP)) {
	module_conninfo_tcb *ptcbc;
	struct tcplibstats *pstats;
	int dir;

/* 	printf("NewConn, saw btype %d for %s\n", btype, */
/* 	       FormatBrief(ptp)); */
	

	for (LOOP_OVER_BOTH_TCBS(dir)) {
	    ptcbc = &pmc->tcb_cache[dir];
	    pstats = global_pstats[ptcbc->dtype];

	    if (btype == TCPLIBPORT_NNTP) {
		ptcbc->pburst = &pstats->nntp_bursts;
	    } else if (btype == TCPLIBPORT_HTTP) {
		/* assume 1.1 unless we see parallelism later */
		ptcbc->pburst = &pstats->http_S_bursts;
	    }

	    ptcbc->last_data_time = current_time;
	}
    }


    /* debugging counter */
    if (btype == TCPLIBPORT_HTTP)
	++debug_http_total;


    /* add to list of endpoints we track */
    TrackEndpoints(pmc);

    /* if it's NOT trafgen generated and it's HTTP, check if it's
       parallel */
    if (is_http_conn(pmc) && !trafgen_generated) {
	if (is_parallel_http(pmc)) {
	    pmc->ignore_conn = TRUE;
	}
    }


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
\t  -H       use hacks to find data from trafgen-generated files\n\
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
    enum t_dtype ix;
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
	char *prefix = dtype_names[ix];
	char *filename = namedfile(prefix,TCPLIB_BREAKDOWN_GRAPH_FILE);

	if (!(pstats->hist_file = Mfopen(filename, "w"))) {
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
    Mfprintf(pstats->hist_file, "%d\t", pstats->interval_count);

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
	    Mfprintf(pstats->hist_file, "%c", breakdown_hash_char[i]);
	    count--;
	}
    }

    /* After we've done all the applications, end the line */
    Mfprintf(pstats->hist_file, "\n");

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
	snprintf(directory,sizeof(directory),"%s_%s", output_dir, localsuffix);
    else
	snprintf(directory,sizeof(directory),"%s", output_dir);

    /* try to CREATE the directory if it doesn't exist */
    if (access(directory,F_OK) != 0) {
	if (mkdir(directory,0755) != 0) {
	    perror(directory);
	    exit(-1);
	}
	if (ldebug>1)
	    printf("Created directory '%s'\n", directory);
    }

    snprintf(buffer,sizeof(buffer),"%s/%s", directory, real);

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
    MFILE* fil;        /* File descriptor for the traffic breakdown file */
    long file_pos;    /* Offset within the traffic breakdown file */
    u_long num_parallel_http = 0;


    /* This is the header for the traffic breakdown file.  It follows the
     * basic format of the original TCPLib breakdown file, but has been
     * modified to accomodate the additions that were made to TCPLib */
#ifdef INCLUDE_PHONE_CONV
    char *header = "stub\tsmtp\tnntp\ttelnet\tftp\thttp\tphone\tconv\n";
#else /* INCLUDE_PHONE_CONV */
    char *header = "stub             smtp\tnntp\ttelnet\tftp\thttp\n";
#endif /* INCLUDE_PHONE_CONV */

    if (!(fil = Mfopen(filename, "a"))) {
	perror("Opening Breakdown File");
	exit(1);
    }

    Mfseek(fil, 0, SEEK_END);
    file_pos = Mftell(fil);

    /* Basically, we're checking to see if this file has already been
     * used.  We have the capability to both start a new set of data
     * based on a trace file, or we have the ability to incorporate one
     * trace file's data into the data from another trace.  This would
     * have the effect of creating a hybrid traffic pattern, that matches
     * neither of the sources, but shares characteristics of both. */
    if (file_pos < strlen(header)) {
	Mfprintf(fil, "%s", header);
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
	Mfprintf(fil, "%-16s ", current_file);

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

	    /* count the parallel HTTP separately */
	    if (pmc->ignore_conn) {
		if (protocol_type == TCPLIBPORT_HTTP) {
		    ++num_parallel_http;
		    continue;
		}
	    }

	    /* see if we want A->B */
	    ptcbc = &pmc->tcb_cache[TCB_CACHE_A2B];
	    if ((*p_tester)(pmc, ptcbc)) {
		/* count it if there's data */
		if (ptcbc->data_bytes > 0) {
		    if (pmc->ignore_conn && is_http_conn(pmc))
			++num_parallel_http;
		    else
			++breakdown_protocol[protocol_type];
		} else {
		    ++no_data;
		}
	    } else {
		/* see if we want B->A */
		ptcbc = &pmc->tcb_cache[TCB_CACHE_B2A];
		if ((*p_tester)(pmc, ptcbc)) {
		    /* count it if there's data */
		    if (ptcbc->data_bytes > 0) {
			if (pmc->ignore_conn && is_http_conn(pmc))
			    ++num_parallel_http;
			else
			    ++breakdown_protocol[protocol_type];
		    } else {
			++no_data;
		    }
		} else {
		    ++bad_dir;
		}
	    }
	}

	/* Print out each of the columns we like */
	/* SMTP */
	Mfprintf(fil, "%.4f\t",
		((float)breakdown_protocol[TCPLIBPORT_SMTP])/ num_tcp_pairs);

	/* NNTP */
	Mfprintf(fil, "%.4f\t",
		((float)breakdown_protocol[TCPLIBPORT_NNTP])/ num_tcp_pairs);

	/* TELNET */
	Mfprintf(fil, "%.4f\t",
		((float)breakdown_protocol[TCPLIBPORT_TELNET])/ num_tcp_pairs);

	/* FTP */
	Mfprintf(fil, "%.4f\t",
		((float)breakdown_protocol[TCPLIBPORT_FTPCTRL])/ num_tcp_pairs);

	/* HTTP */
	Mfprintf(fil, "%.4f\t",
		((float)breakdown_protocol[TCPLIBPORT_HTTP])/ num_tcp_pairs);

#ifdef UNDEF
	/* FTP Data */
	Mfprintf(fil, "%.4f\t",
		((float)breakdown_protocol[TCPLIBPORT_FTPDATA])/ num_tcp_pairs);

	/* Parallel HTTP */
	Mfprintf(fil, "%.4f\t",
		((float)num_parallel_http)/ num_tcp_pairs);
#endif /* UNDEF */

#ifdef INCLUDE_PHONE_CONV
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
	Mfprintf(fil, "%.4f\t%.4f", (float)0, (float)0);
#endif /* INCLUDE_PHONE_CONV */
	Mfprintf(fil, "\n");

    }

    Mfclose(fil);
    Mfclose(pstats->hist_file);
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
    enum t_dtype dtype;
    int etime;   /* Time difference between the first packet in this
		  * conversation and the first packet in the previous
		  * conversation.  Basically, this is the time between
		  * new conversations. */

    /* see where to keep the stats */
    dtype = traffic_type(pmc, ptcbc);
    pstats = global_pstats[dtype];

    if (ldebug>2) {
	printf("do_tcplib_next_converse: %s, %s\n",
	       FormatBrief(pmc->ptp, ptcbc->ptcb), dtype_names[dtype]);
    }


    /* sdo - Wed Jun 16, 1999 */
    /* new method, search backward to find the previous connection that had */
    /* data flowing in the same "direction" and then use the difference */
    /* between the starting times of those two connections as the conn */
    /* interrival time */
    /* sdo - Fri Jul  9, 1999 (information already computed in Fillcache) */

    /* FIRST, do conversation interarrivals for ALL conns */
    if (ptcbc->prev_dtype_all != NULL) {
	pmc_previous = ptcbc->prev_dtype_all;
	/* elapsed time since that previous connection started */
	etime = (int)(elapsed(pmc_previous->first_time,
			      pmc->first_time)/1000.0); /* convert us to ms */

	/* keep stats */
	AddToCounter(&pstats->conv_interarrival_all, etime, 1, 1);
    }


    /* THEN, do conversation interarrivals by APP type */
    if (ptcbc->prev_dtype_byapp != NULL) {
	pmc_previous = ptcbc->prev_dtype_byapp;
	/* elapsed time since that previous connection started */
	etime = (int)(elapsed(pmc_previous->first_time,
			      pmc->first_time)/1000.0); /* convert us to ms */

	/* keep stats */
	AddToCounter(&pstats->conv_interarrival_byapp[pmc->btype],
		     etime, 1, 1);
    }

    return;
}

/* End of the breakdown section */


/* return the previous connection that passes data in the direction */
/* given in "dtype" and has app type apptype (or -1 for any) */
module_conninfo *
FindPrevConnection(
    module_conninfo *pmc,
    enum t_dtype dtype,
    int app_type)
{
    module_conninfo_tcb *ptcbc;
    int count = 0;

    /* loop back further in time */
    for (pmc = pmc->prev; pmc; pmc = pmc->prev) {
	int dir;

	/* ignore FTP Data and parallel HTTP */
	if (pmc->ignore_conn)
	    continue;
	
	for (LOOP_OVER_BOTH_TCBS(dir)) {
	    ptcbc = &pmc->tcb_cache[dir];
	    if ((app_type != -1) && (app_type != pmc->btype)) {
		/* skip it, wrong app */
	    }
	    if (ptcbc->dtype == dtype) {
		if (ptcbc->data_bytes != 0)
		    return(pmc);
	    }

	    if (ldebug)
		++count;
	}
    }

    if (ldebug > 1)
	printf("FindPrevConnection %s returned NULL, took %d searches\n",
	       dtype_names[dtype], count);

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
    char *protocol,
    dyn_counter psizes)
{
    const int bucketsize = GRAN_CONVARRIVAL;
    char title[80];


#ifdef READ_OLD_FILES
    /* sdo - OK, pstats->conv_interarrival already has the counts we */
    /* made.  First, include anything from an existing file. */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);
#endif /* READ_OLD_FILES */

    /* generate the graph title of the table */
    snprintf(title,sizeof(title),"Conversation Interval Time (ms) - %s", protocol);

    /* Now, dump out the combined data */
    StoreCounters(filename,title, "% Interarrivals", bucketsize, psizes);

    return;
}

static void
do_tcplib_conv_duration(
    char *filename,
    dyn_counter psizes)
{
    const int bucketsize = GRAN_CONVDURATION;

#ifdef READ_OLD_FILES
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);
#endif /* READ_OLD_FILES */

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
    enum t_dtype dtype;
    int etime;   /* Time difference between the first packet in this
		  * conversation and the last packet */

    /* see where to keep the stats */
    dtype = traffic_type(pmc, ptcbc);
    pstats = global_pstats[dtype];

    if (ldebug>2) {
	printf("do_tcplib_next_duration: %s, %s\n",
	       FormatBrief(pmc->ptp, ptcbc->ptcb), dtype_names[dtype]);
    }


    /* elapsed time since that previous connection started */
    etime = (int)(elapsed(pmc->first_time,
			  pmc->last_time)/1000.0); /* convert us to ms */

    /* keep stats */
    AddToCounter(&pstats->conv_duration, etime, 1, GRAN_CONVDURATION);
    
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
/*       case IPPORT_SSH: */ /* not considered safe to assume -- sdo */
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
    const int bucketsize = GRAN_TELNET_DURATION;
    module_conninfo *pmc;
    

#ifdef READ_OLD_FILES
    /* This section reads in the data from the existing telnet duration
     * file in preparation for merging with the current data. */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);
#endif /* READ_OLD_FILES */


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
	    AddToCounter(&psizes, temp, 1, bucketsize);
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
	int dir;

	if (ldebug>2) {
	    static int count = 0;
	    printf("do_all_conv_arrivals: processing pmc %d: %p\n",
		   ++count, pmc);
	}

	/* ignore unidirectional HTTP */
	if (is_http_conn(pmc) && pmc->unidirectional_http)
	    continue;


	for (LOOP_OVER_BOTH_TCBS(dir)) {
	    if (pmc->tcb_cache[dir].data_bytes != 0) {
		do_tcplib_next_converse(&pmc->tcb_cache[dir], pmc);
		do_tcplib_next_duration(&pmc->tcb_cache[dir], pmc);
	    }
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
    (void) AddToCounter(psizes, temp, 1, 1);

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
    const int bucketsize = GRAN_TELNET_ARRIVAL;
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



#ifdef READ_OLD_FILES
    /* add in the data from the old run (if it exists) */
    psizes = ReadOldFile(filename, bucketsize, MAX_TEL_INTER_COUNT, psizes);
#endif /* READ_OLD_FILES */


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
    const int bucketsize = GRAN_TELNET_PACKETSIZE;
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


#ifdef READ_OLD_FILES
    /* In this section, we're reading in from the previous data file,
     * applying the data contained there to the data set that we've 
     * acquired during this run, and then dumping the merged data set
     * back out to the data file */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);
#endif /* READ_OLD_FILES */


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
    AddToCounter(&pstats->telnet_pktsize, length, 1, 1);
}


/* End Telnet Stuff */








/* Begin FTP Stuff */

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
    const int bucketsize = GRAN_FTP_ITEMSIZE;

    tcplib_do_GENERIC_itemsize(filename, TCPLIBPORT_FTPDATA,
			       p_tester, bucketsize);
}


void tcplib_do_ftp_numitems(
    char *filename,		/* where to store the output */
    f_testinside p_tester)	/* functions to test "insideness" */
{
    int bucketsize = GRAN_NUMITEMS;
    module_conninfo *pmc;
    dyn_counter psizes = NULL;
    

#ifdef READ_OLD_FILES
    /* If an old data file exists, open it, read in its contents
     * and store them until they are integrated with the current
     * data */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);
#endif /* READ_OLD_FILES */


    /* fill out the array with data from the current connections */
    for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	/* We only need the stats if it's the right port */
	if (is_ftp_ctrl_conn(pmc)) {
	    if ((*p_tester)(pmc, &pmc->tcb_cache[TCB_CACHE_A2B])) {
		if (ldebug && (pmc->tcb_cache[TCB_CACHE_A2B].numitems == 0))
			printf("numitems: control %s has NONE\n",
			       FormatBrief(pmc->ptp, NULL));
		AddToCounter(&psizes, pmc->tcb_cache[TCB_CACHE_A2B].numitems,
			     1, 1);
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
    const int bucketsize = GRAN_FTP_CTRLSIZE;

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
    const int bucketsize = GRAN_SMTP_ITEMSIZE;

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



/***************************************************************************
 **
 ** Support Routines
 **
 ***************************************************************************/


/***************************************************************************
 *
 * StoreCounters -- store a dyncounter structure into a file
 *   this get's a little interesting because of the way tcplib works
 *   for example, given the simple table
 *	1 0.3333
 *	2 0.6667
 *	3 1.0000
 *   tcplib will generate integer samples (from a random test):
 *	1	66756	0.6676	0.6676
 *	2	33244	0.3324	1.0000
 *
 *   as another example, given the simple table (same as before except
 *   for the first line)
 *	0 0.0000
 *	1 0.3333
 *	2 0.6667
 *	3 1.0000
 *   tcplib will generate integer samples (from a random test):
 *	0	33609	0.3361	0.3361
 *	1	33044	0.3304	0.6665
 *	2	33347	0.3335	1.0000
 *   SO... if we really want 1/3 1's, 2's, and 3's, we need the table:
 *	1 0.0000
 *	2 0.3333
 *	3 0.6667
 *	4 1.0000
 *    and a random test gives us
 *	1	33609	0.3361	0.3361
 *	2	33044	0.3304	0.6665
 *	3	33347	0.3335	1.0000
 *    which is exactly what we wanted.
 *
 *    ... therefore, for each counter, we store counter+GRANULARITY
 *    in the table, and also store a 0.0000 value for the FIRST entry
 * 
 **************************************************************************/
static void
StoreCounters(
    char *filename,
    char *header1,
    char *header2,
    int bucketsize,
    dyn_counter psizes)
{
    MFILE *fil;
    int running_total = 0;
    int lines = 0;

    if (ldebug>1)
	printf("Saving data for file '%s'\n", filename);

    /* verify bucketsize, but not needed anymore */
    if (bucketsize != GetGran(psizes)) {
	/* probably because the counter was never used */
	if (GetTotalCounter(psizes) != 0) {
	    fprintf(stderr,"StoreCounters: bad bucketsize (%s)\n",
		    filename);
	    exit(-1);
	}
    }

    if (!(fil = Mfopen(filename, "w"))) {
	perror(filename);
	exit(1);
    }

    Mfprintf(fil, "%s\t%s\tRunning Sum\tCounts\n", header1, header2);

    if (psizes == NULL) {
	if (ldebug>1)
	    printf("  (No data for file '%s')\n", filename);
    } else {
	int cookie = 0;
	int first = TRUE;
	while (1) {
	    u_long ix;
	    int value;
	    u_long count;
	    u_long total_counter = GetTotalCounter(psizes);
	    u_long gran = GetGran(psizes);

	    if (NextCounter(&psizes, &cookie, &ix, &count) == 0)
		break;

	    value = ix;
	    running_total += count;

	    if (count) {
		if (first) {
		    /* see comments above! */
		    Mfprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
			     (float)(value), 0.0, 0, 0);
		    first = FALSE;
		}
		Mfprintf(fil, "%.3f\t%.4f\t%d\t%lu\n",
			 (float)(value+gran),
			 (float)running_total/(float)total_counter,
			 running_total,
			 count);
		++lines;
	    }
	}
    }

    Mfclose(fil);

    if (ldebug>1)
	printf("  Stored %d values into %d lines of '%s'\n",
	       running_total, lines, filename);
}


#ifdef READ_OLD_FILES
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
#endif /* READ_OLD_FILES */


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
    

#ifdef READ_OLD_FILES
    /* If an old data file exists, open it, read in its contents
     * and store them until they are integrated with the current
     * data */
    psizes = ReadOldFile(filename, bucketsize, 0, psizes);
#endif /* READ_OLD_FILES */


    /* fill out the array with data from the current connections */
    for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	/* We only need the stats if it's the right breakdown type */
	if (pmc->btype == btype) {
	    int nbytes = InsideBytes(pmc,p_tester);

	    /* if there's no DATA, don't count it!  (sdo change!) */
	    if (nbytes != 0)
		AddToCounter(&psizes, nbytes, 1, bucketsize);
	}
    }


    /* store all the data (old and new) into the file */
    StoreCounters(filename,"Article Size (bytes)", "% Articles",
		  bucketsize,psizes);

    /* free the dynamic memory */
    DestroyCounters(&psizes);
}



/* cleanup all the burstsize counters */
/* called for HTTP_P, HTTP_S, and NNTP */
static void
tcplib_cleanup_bursts()
{
    module_conninfo *pmc;

    /* all but the last burst was ALREADY recorded, so we just clean
       up any burst that might be left */
    for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	int dir;

	for (LOOP_OVER_BOTH_TCBS(dir)) {
	    module_conninfo_tcb *ptcbc = &pmc->tcb_cache[dir];

	    /* check for burst data */
	    if (ptcbc->pburst == NULL)
		continue;

	    /* count the LAST burst */
	    if (ptcbc->burst_bytes != 0) {
		++ptcbc->numitems;
	    }

	    /* add the last burst into the ttl for the parallel stream */
	    if (ptcbc->burst_bytes != 0) {
		struct parallelism *pp = pmc->pparallelism;
		if (pp) {
		    ++pp->ttlitems[dir];
		}
	    }


	    if (ptcbc->burst_bytes != 0) {
		AddToCounter(&ptcbc->pburst->size,
			     ptcbc->burst_bytes,
			     1, GRAN_BURSTSIZE);
	    }

	    if (ptcbc->numitems != 0) {
		AddToCounter(&ptcbc->pburst->nitems,
			     ptcbc->numitems,
			     1,GRAN_NUMITEMS);
	    }
	}
    }
}
/* both ftp and nntp look the same */
static void
tcplib_do_GENERIC_burstsize(
    char *filename,		/* where to store the output */
    dyn_counter counter)
{
    int bucketsize = GRAN_BURSTSIZE;


    /* store all the data (old and new) into the file */
    StoreCounters(filename,"Burst Size", "% Bursts",
		  bucketsize, counter);
}
static void
tcplib_do_GENERIC_P_maxconns(
    char *filename,		/* where to store the output */
    dyn_counter counter)
{
    int bucketsize = GRAN_MAXCONNS;

    /* store all the data (old and new) into the file */
    StoreCounters(filename,"Max Conns", "% Streams",
		  bucketsize, counter);
}
static void
tcplib_do_GENERIC_nitems(
    char *filename,		/* where to store the output */
    dyn_counter counter)
{
    int bucketsize = GRAN_NUMITEMS;

    /* store all the data (old and new) into the file */
    StoreCounters(filename,"Num Items", "% Conns",
		  bucketsize, counter);
}
/* both ftp and nntp look the same */
static void
tcplib_do_GENERIC_idletime(
    char *filename,		/* where to store the output */
    dyn_counter counter)
{
    int bucketsize = GRAN_BURSTIDLETIME;

    /* store all the data (old and new) into the file */
    StoreCounters(filename,"Idle Time", "% Bursts",
		  bucketsize, counter);
}

static enum t_dtype
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
    tcp_pair *ptp,
    tcb *ptcb)
{
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;
    static char infobuf[100];

    if (ptcb == pba)
	snprintf(infobuf,sizeof(infobuf),"%s - %s (%s2%s)",
		ptp->b_endpoint, ptp->a_endpoint,
		pba->host_letter, pab->host_letter);
    else
	snprintf(infobuf,sizeof(infobuf),"%s - %s (%s2%s)",
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

    snprintf(infobuf1,sizeof(infobuf1),"%s", HostName(paddr_pair->a_address));
    snprintf(infobuf2,sizeof(infobuf2),"%s", HostName(paddr_pair->b_address));
    snprintf(infobuf,sizeof(infobuf),"%s - %s", infobuf1, infobuf2);

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



/* remove unidirectional conns from consideration */
static void
tcplib_filter_http_uni()
{
    module_conninfo *pmc;

    for (pmc = module_conninfo_tail; pmc; pmc = pmc->prev) {
	if ((pmc->tcb_cache[0].data_bytes == 0) ||
	    (pmc->tcb_cache[1].data_bytes == 0)) {
	    /* unidirectional (or no data at all) */
	    pmc->unidirectional_http = TRUE;

	    /* update counters */
	    ++debug_http_uni_conns;
	    debug_http_uni_bytes +=
		pmc->tcb_cache[0].data_bytes +
		pmc->tcb_cache[1].data_bytes;

	    /* UNDO other counters */
	    --debug_http_total;
	    if (pmc->pparallelism &&
		(pmc->pparallelism->maxparallel > 1)) {
		--pmc->pparallelism->maxparallel;
		--debug_http_parallel;

		/* if this is NOT the last one, decrement slave count */
		if (pmc->pparallelism->maxparallel > 0) {
		    --debug_http_slaves;
		} else {
		    /* nobody left, empty group */
		    --debug_http_groups;
		}
	    }

	    /* persistance is OK, as those are already ignored
	       in tcplib_save_bursts */

	}
    }
}


static Bool
is_parallel_http(
    module_conninfo *pmc_new)
{
    endpoint_pair *pep;
    module_conninfo *pmc;
    struct parallelism *pp = NULL;
    int dir;
    int parallel_conns = 0;
    u_long parent_groupnum = 0;

    /* see if there are any other connections on these endpoints */
    pep = FindEndpointPair(http_endpoints, &pmc_new->addr_pair);

    /* if none, we're done */
    if (pep == NULL)
	return(FALSE);

    /* search that pep chain for PARALLEL conns */
    for (pmc = pep->pmchead; pmc; pmc = pmc->next_pair) {

	/* for efficiency, as we search we remove old, inactive entries */
	/* NOTE that this is the NEXT entry, not current */
	if (pmc->next_pair) {
	    if (!RecentlyActiveConn(pmc->next_pair)) {
		/* remove it (by linking around it) */
		pmc->next_pair = pmc->next_pair->next_pair;
	    }
	}

	/* if it's ME or it's not ACTIVE, skip it */
	if ((pmc_new == pmc) || !RecentlyActiveConn(pmc))
	    continue;

	if (trafgen_generated) {
	    /* burst key group nums must also be the same */
	    if (pmc_new->http_groupnum != pmc->http_groupnum) {
		continue;	/* skip it */
	    }
	}


	/* OK, it's ACTIVE */

	/* mark it as parallel if not already done */
	if (pmc->pparallelism == NULL) {
	    pmc->pparallelism = MallocZ(sizeof(struct parallelism));

	    /* if HE isn't marked, then he must be the "parent",
	       and this must be a new group */
	    ++debug_http_groups;
	    ++debug_http_parallel;

	    /* if this isn't trafgen-generated, give it a group number */
	    /* (mostly for debugging) */
	    if (!trafgen_generated) {
		static u_long groupnum = 0;
		parent_groupnum = ++groupnum;
		pmc->http_groupnum = parent_groupnum;
	    }
	      

	    /* switch its stats to parallel */
	    for (LOOP_OVER_BOTH_TCBS(dir)) {
		module_conninfo_tcb *ptcbc = &pmc->tcb_cache[dir];
		struct tcplibstats *pstats = global_pstats[ptcbc->dtype];
		ptcbc->pburst = &pstats->http_P_bursts;
	    }
	} else {
	    /* it's already known to be parallel, so he's my brother */
	    if (!trafgen_generated) {
		parent_groupnum = pmc->http_groupnum;
	    }
	}

	/* remember the parallel struct for these connections */
	pp = pmc->pparallelism;

	/* sanity check, if we've already found one, it better be */
	/* the same as this one!! */
	if ((pp != NULL) && (pp != pmc->pparallelism)) {
	    fprintf(stderr,"FindParallelHttp: bad data structure!!\n");
	    exit(-1);
	}

	/* found one more */
	++parallel_conns;
    }

    /* if we didn't find any, we're done */
    if (parallel_conns == 0)
	return(FALSE);

    /* mark ME as parallel too */
    ++debug_http_slaves;
    ++debug_http_parallel;
    for (LOOP_OVER_BOTH_TCBS(dir)) {
	module_conninfo_tcb *ptcbc = &pmc_new->tcb_cache[dir];
	struct tcplibstats *pstats = global_pstats[ptcbc->dtype];
	ptcbc->pburst = &pstats->http_P_bursts;
    }

/*     printf("FindParallel, marking as parallel %s\n",  */
/* 	   FormatBrief(pmc_new->ptp)); */

    /* if this isn't trafgen generated, take the group number */
    pmc_new->http_groupnum = parent_groupnum;
	

    /* update stats on this parallel system */
    pmc_new->pparallelism = pp;
    ++parallel_conns;	/* include ME */

    /* update maximum parallelism, if required */
    if (parallel_conns > pmc_new->pparallelism->maxparallel)
	pmc_new->pparallelism->maxparallel = parallel_conns;

    /* this _IS_ parallel */
    return(TRUE);
}


static void
TrackEndpoints(
    module_conninfo *pmc)
{
    /* remember the endpoints (ftp and HTTP) */
    if (is_ftp_ctrl_conn(pmc)) {
	AddEndpointPair(ftp_endpoints,pmc);
    } else if (is_http_conn(pmc)) {
	AddEndpointPair(http_endpoints,pmc);
    }

    /* if it's an FTP data connection, find the control conn */
    if (is_ftp_data_conn(pmc)) {
	endpoint_pair *pep;

	/* for FTP Data, we ignore this one */
	pmc->ignore_conn = TRUE;

	pep = FindEndpointPair(ftp_endpoints, &pmc->addr_pair);

	if (pep) {
	    /* "charge" this new DATA connection to the most
	       recently-active ftp control connection */
	    struct module_conninfo_tcb *tcbc_control;
	    tcbc_control = MostRecentFtpControl(pep);
	    ++tcbc_control->numitems;
	    if (ldebug>1) {
		printf("Charging ftp data to %s, count %lu\n",
		       FormatBrief(tcbc_control->ptcb->ptp,
				   tcbc_control->ptcb),
		       tcbc_control->numitems);
	    }
	} else {
	    if (ldebug>1)
		fprintf(stderr,"WARNING: no FTP control conn for %s???\n",
			FormatBrief(pmc->ptp, NULL));
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
    ++debug_newconn_ftp_data_heuristic;
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
	    tcbc_newest = &pmc->tcb_cache[TCB_CACHE_A2B];
	    time_newest = tcb_newest->last_data_time;
	} else if (tv_gt(ptcb_client->last_data_time, time_newest)) {
	    /* this is "most recent" */
	    tcb_newest = ptcb_client;
	    tcbc_newest = &pmc->tcb_cache[TCB_CACHE_A2B];
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
 *  1) All previous data was ACKed
 *  2) There was intervening data in the other direction
 *  3) idletime > RTT
 */
static Bool
IsNewBurst(
    module_conninfo *pmc,
    tcb *ptcb,
    module_conninfo_tcb *ptcbc,
    struct tcphdr *tcp)
{
    seqnum seq = ntohl(tcp->th_seq);
    tcb *orig_lastdata;

    tcb *ptcb_otherdir = ptcb->ptwin;


    /* remember the last direction the data flowed */
    orig_lastdata = pmc->tcb_lastdata;
    pmc->tcb_lastdata = ptcb;


    if (graph_tsg) {
	plotter_perm_color(ptcb->tsg_plotter, "green");
	plotter_text(ptcb->tsg_plotter, current_time, seq, "a", "?");
    }

    /* it's only a NEW burst if there was a PREVIOUS burst */
    if (ptcbc->burst_bytes == 0) {
	if (graph_tsg)
	    plotter_text(ptcb->tsg_plotter, current_time, seq, "b", "==0");
	return(FALSE);
    }

    /* check for old data ACKed */
    if (SEQ_LESSTHAN(ptcb_otherdir->ack,seq)) {
	/* not ACKed */
	if (graph_tsg)
	    plotter_text(ptcb->tsg_plotter, current_time, seq, "b", "noack");
	return(FALSE);
    }

    /* check for idletime > RTT */
    {
	u_long etime_usecs = elapsed(ptcbc->last_data_time, current_time);
	u_long last_rtt_usecs = ptcb->rtt_last;
	if ((last_rtt_usecs != 0) && (etime_usecs < last_rtt_usecs)) {
	    if (graph_tsg) {
		char buf[100];
		snprintf(buf,sizeof(buf),"short (%ld < %ld)", etime_usecs, last_rtt_usecs);
		plotter_text(ptcb->tsg_plotter, current_time, seq, "b", buf);
	    }
	    return(FALSE);
	}
    }

    /* check for intervening data */
    if (ptcb == orig_lastdata) {
	/* no intervening data */
	if (graph_tsg)
	    plotter_text(ptcb->tsg_plotter, current_time, seq, "b", "!data");
	return(FALSE);
    }

    /* ... else, it's a new burst */

    if (graph_tsg) {
	plotter_perm_color(ptcb->tsg_plotter, "magenta");
	plotter_text(ptcb->tsg_plotter, current_time, seq, "r", "YES!!");
    }
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


/* is this connection "parallel" */
/* 1: ActiveConn() */
/* 2: last packets sent "recently" (defined as within 10 seconds) */
static Bool
RecentlyActiveConn(
    module_conninfo *pmc)
{
    int dir;
    
    if (ActiveConn(pmc))
	return(TRUE);

    for (LOOP_OVER_BOTH_TCBS(dir)) {
	timeval last_packet = pmc->tcb_cache[dir].ptcb->last_time;

	/* elapsed time from last packet (in MICROseconds) */
	if (elapsed(last_packet,current_time) < 10*US_PER_SEC) {
	    /* 10 seconds for now, hope it works! */
	    return(TRUE);
	}
    }
    
    return(FALSE);
}


#endif /* LOAD_MODULE_TCPLIB */
