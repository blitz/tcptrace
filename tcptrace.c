/*
 * Copyright (c) 1994, 1995, 1996
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
    "@(#)Copyright (c) 1996 -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


#include "tcptrace.h"
#include "file_formats.h"
#include "modules.h"
#include "version.h"


/* version information */
char *tcptrace_version = VERSION;


/* local routines */
static void Args(void);
static void ModulesPerPacket(struct ip *pip, tcp_pair *ptp, void *plast);
static void ModulesPerConn(tcp_pair *ptp);
static void ModulesPerFile(char *filename);
static void DumpFlags(void);
static void ExplainOutput(void);
static void FinishModules(void);
static void Formats(void);
static void Help(char *harg);
static void Hints(void);
static void ListModules(void);
static void LoadModules(int argc, char *argv[]);
static void ParseArgs(int *pargc, char *argv[]);
static void ProcessFile(char *filename);
static void QuitSig(int signum);
static void Usage(char *prog);
static void Version(void);


/* option flags and default values */
Bool colorplot = TRUE;
Bool dump_rtt = FALSE;
Bool graph_rtt = FALSE;
Bool graph_tput = FALSE;
Bool graph_tsg = FALSE;
Bool hex = TRUE;
Bool ignore_non_comp = FALSE;
Bool print_rtt = FALSE;
Bool print_cwin = FALSE;
Bool printbrief = TRUE;
Bool printsuppress = FALSE;
Bool printem = FALSE;
Bool printticks = FALSE;
Bool printtrunc = FALSE;
Bool save_tcp_data = FALSE;
Bool graph_time_zero = FALSE;
int debug = 0;
u_long beginpnum = 0;
u_long endpnum = ~0;
int pnum = 0;
int ctrunc = 0;

/* globals */
struct timeval current_time;
int num_modules = 0;
char *ColorNames[NCOLORS] =
{"green", "red", "blue", "yellow", "purple", "orange", "magenta", "pink"};


/* locally global variables */
static u_long filesize = -1;
char **filenames;



static void
Help(
    char *harg)
{
    if (harg && *harg && strncmp(harg,"arg",3) == 0) {
	Args();
    } else if (harg && *harg && strncmp(harg,"conf",4) == 0) {
	Formats();
	CompFormats();
	ListModules();
    } else if (harg && *harg && strncmp(harg,"out",3) == 0) {
	ExplainOutput();
    } else if (harg && *harg &&
	       ((strncmp(harg,"hint",4) == 0) || (strncmp(harg,"int",3) == 0))) {
	Hints();
    } else {
	fprintf(stderr,"\
For help on specific topics, try:  \n\
  -hargs    tell me about the program's arguments  \n\
  -hconfig  tell me about the configuration of this binary  \n\
  -houtput  explain what the output means  \n\
  -hhints   usage hints  \n");
    }

    fprintf(stderr,"\n");
    Version();
    exit(0);
}


static void
Usage(
    char *prog)
{
    fprintf(stderr,"usage: %s [args...]* dumpfile [more files]*\n", prog);

    Help(NULL);

    exit(-2);
}


static void
ExplainOutput(void)
{
    fprintf(stderr,"\n\
OK, here's a sample output (using -l) and what each line means:\n\
\n\
1 connection traced:\n\
              ####   how many distinct TCP connections did I see pieces of\n\
13 packets seen, 13 TCP packets traced\n\
              ####   how many packets did I see, how many did I trace\n\
connection 1:\n\
              #### I'll give you a separate block for each connection,\n\
              #### here's the first one\n\
	host a:        132.235.3.133:1084\n\
	host b:        132.235.1.2:79 \n\
              #### Each connection has two hosts.  To shorten output\n\
              #### and file names, I just give them letters.\n\
              #### Connection 1 has hosts 'a' and 'b', connection 2\n\
              #### has hosts 'c' and 'd', etc.\n\
	complete conn: yes\n\
              #### Did I see the starting FINs and closing SYNs?  Was it reset?\n\
	first packet:  Wed Jul 20 16:40:30.688114\n\
              #### At what time did I see the first packet from this connection?\n\
	last packet:   Wed Jul 20 16:40:41.126372\n\
              #### At what time did I see the last packet from this connection?\n\
	elapsed time:  0:00:10.438257\n\
              #### Elapsed time, first packet to last packet\n\
	total packets: 13\n\
              #### total packets this connection\n\
\n\
              #### ... Now, there's two columns of output (TCP is\n\
              #### duplex) one for each direction of packets.\n\
              #### I'll just explain one column...\n\
   a->b:			      b->a:\n\
     total packets:             7           total packets:             6\n\
              #### packets sent in each direction\n\
     ack pkts sent:             6           ack pkts sent:             6\n\
              #### how many of the packets contained a valid ACK\n\
     unique bytes sent:        11           unique bytes sent:      1152\n\
              #### how many data bytes were sent (not counting retransmissions)\n\
     actual data pkts:          2           actual data pkts:          1\n\
              #### how many packets did I see that contained any amount of data\n\
     actual data bytes:        11           actual data bytes:      1152\n\
              #### how many data bytes did I see (including retransmissions)\n\
     rexmt data pkts:           0           rexmt data pkts:           0\n\
              #### how many data packets were retransmissions\n\
     rexmt data bytes:          0           rexmt data bytes:          0\n\
              #### how many bytes were retransmissions\n\
     outoforder pkts:           0           outoforder pkts:           0\n\
              #### how many packets were out of order (or I didn't see the first transmit!)\n\
     SYN/FIN pkts sent:       1/1           SYN/FIN pkts sent:       1/1\n\
              #### how many SYNs and FINs were sent in each direction\n\
     mss requested:          1460 bytes     mss requested:          1460 bytes\n\
              #### What what the requested Maximum Segment Size\n\
     max segm size:             9 bytes     max segm size:          1152 bytes\n\
              #### What was the largest segment that I saw\n\
     min segm size:             2 bytes     min segm size:          1152 bytes\n\
              #### What was the smallest segment that I saw\n\
     avg segm size:             5 bytes     avg segm size:          1150 bytes\n\
              #### What was the average segment that I saw\n\
     max win adv:            4096 bytes     max win adv:            4096 bytes\n\
              #### What was the largest window advertisement that I sent\n\
     min win adv:            4096 bytes     min win adv:            4085 bytes\n\
              #### What was the smallest window advertisement that I sent\n\
     zero win adv:              0 times     zero win adv:              0 times\n\
              #### How many times did I sent a zero-sized window advertisement\n\
     avg win adv:            4096 bytes     avg win adv:            4092 bytes\n\
              #### What was the average window advertisement that I sent\n\
     initial window:            9 bytes     initial window:         1152 bytes\n\
              #### How many bytes in the first window (before the first ACK)\n\
     initial window:            1 pkts      initial window:            1 pkts\n\
              #### How many packets in the first window (before the first ACK)\n\
     throughput:                1 Bps       throughput:              110 Bps\n\
              #### What was the data throughput (Bytes/second)\n\
     ttl stream length:        11 bytes     ttl stream length:      1152 bytes\n\
              #### What was the total length of the stream (from FIN to SYN)\n\
              #### Note that this might be larger than unique data bytes because\n\
              #### I might not have captured every segment!!!\n\
     missed data:               0 bytes     missed data:               0 bytes\n\
              #### How many bytes of data were in the stream that I didn't see?\n\
     RTT samples:               2           RTT samples:               1\n\
              #### How many ACK's could I use to get an RTT sample\n\
     RTT min:                45.9 ms        RTT min:                19.4 ms\n\
              #### What was the smallest RTT that I saw\n\
     RTT max:               199.0 ms        RTT max:                19.4 ms\n\
              #### What was the largest RTT that I saw\n\
     RTT avg:               122.5 ms        RTT avg:                19.4 ms\n\
              #### What was the average RTT that I saw\n\
     RTT stdev:               0.0 ms        RTT stdev:               0.0 ms\n\
              #### What was the standard deviation of the RTT that I saw\n\
     segs cum acked:            0           segs cum acked:            0\n\
              #### How many segments were cumulatively ACKed (the ACK that I saw\n\
	      #### was for a later segment.  Might be a lost ACK or a delayed ACK\n\
     duplicate acks:            2           duplicate acks:            0\n\
              #### How many duplicate ACKs did I see\n\
     max # retrans:             0           max # retrans:             0\n\
              #### What was the most number of times that a single segment\n\
              #### was retransmitted\n\
     min retr time:           0.0 ms        min retr time:           0.0 ms\n\
              #### What was the minimum time between retransmissions of a\n\
              #### single segment\n\
     max retr time:           0.0 ms        max retr time:           0.0 ms\n\
              #### What was the maximum time between retransmissions of a\n\
              #### single segment\n\
     avg retr time:           0.0 ms        avg retr time:           0.0 ms\n\
              #### What was the average time between retransmissions of a\n\
              #### single segment\n\
     sdv retr time:           0.0 ms        sdv retr time:           0.0 ms\n\
              #### What was the stdev between retransmissions of a\n\
              #### single segment\n\
");
}



static void
Hints(void)
{
    fprintf(stderr,"\n\
Hints (in no particular order):\n\
For the first run through a file, just use \"tcptrace file\" to see\n\
   what's there\n\
For large files, use \"-t\" and I'll give you progress feedback as I go\n\
If there's a lot of hosts, particularly if they're non-local, use \"-n\"\n\
   to disable address to name mapping which can be very slow\n\
If you're graphing results and only want the information for a few hosts,\n\
   from a large file, use the -o flag, as in \"tcptrace -o3 -o5\" to only\n\
   process connections 3 and 5.  Writing the graphics files can be slow\n\
Make sure the snap length in the packet grabber is big enough.\n\
     Ethernet headers are 14 bytes, as are several others\n\
     IPv4 headers are at least 20 bytes, but can be as large as 64 bytes\n\
     TCP headers are at least 20 bytes, but can be as large as 64 bytes\n\
   Therefore, if you want to be SURE that you see all of the options,\n\
   make sure that you set the snap length to 14+64+64=142 bytes.  If\n\
   I'm not sure, I usually use 128 bytes.  If you're SURE that there are no\n\
   options (TCP usually has some), you still need at least 54 bytes.\n\
Compress trace files using gzip, I can uncompress them on the fly\n\
");
}


static void
Args(void)
{
    fprintf(stderr,"\n\
Output format options\n\
  -b      brief output format\n\
  -l      long output format\n\
  -r      print rtt statistics (slower for large files)\n\
  -W      report on estimated congestion window (not generally useful)\n\
  -q      no output (if you just want modules output)\n\
Graphing options\n\
  -T      create throughput graph[s], (average over 10 segments, see -A)\n\
  -R      create rtt sample graph[s]\n\
  -S      create time sequence graph[s]\n\
  -G	  create ALL 3 graphs\n\
Output format detail options\n\
  -D      print in decimal\n\
  -X      print in hexidecimal\n\
  -n      don't resolve host or service names (much faster)\n\
  -s      use short names (list \"picard.cs.ohiou.edu\" as just \"picard\")\n\
Connection filtering options\n\
  -iN     ignore connection N (can use multiple times)\n\
  -oN     only connection N (can use multiple times)\n\
  -c      ignore non-complete connections (didn't see syn's and fin's)\n\
  -BN     first segment number to analyze (default 1)\n\
  -EN     last segment number to analyze (default last in file)\n\
Graphing detail options\n\
  -C      produce color plot[s]\n\
  -M      produce monochrome (b/w) plot[s]\n\
  -AN     Average N segments for throughput graphs, default is 10\n\
  -z      plot time axis from 0 rather than wall clock time\n\
Misc options\n\
  -Z      dump raw rtt sample times to file[s]\n\
  -p      print individual packet contents (can be very long)\n\
  -t      'tick' off the packet numbers as a progress indication\n\
  -v      print version information and exit\n\
  -w      print warning message when packets are too short to process\n\
  -d      whistle while you work (enable debug, use -d -d for more output)\n\
  -e      extract contents of each TCP stream into file\n\
  -h      print help messages\n\
  +[v]    reverse the setting of the -[v] flag (for booleans)\n\
Module options\n\
  -xMODULE_SPECIFIC\n\
");
}



static void
Version(void)
{
    fprintf(stderr,"Version: %s\n", tcptrace_version);
    fprintf(stderr,"  Compiled by '%s' at '%s' on machine '%s'\n",
	    built_bywhom, built_when, built_where);
}


static void
Formats(void)
{
    int i;
    
    fprintf(stderr,"Supported Input File Formats:\n");
    for (i=0; file_formats[i].format_name; ++i)
	fprintf(stderr,"\t%-15s  %s\n",
		file_formats[i].format_name,
		file_formats[i].format_descr);
}


static void
ListModules(void)
{
    int i;

    fprintf(stderr,"Included Modules:\n");
    for (i=0; i < NUM_MODULES; ++i) {
	fprintf(stderr,"  %-15s  %s\n",
		modules[i].module_name, modules[i].module_descr);
	if (modules[i].module_usage) {
	    fprintf(stderr,"    usage:\n");
	    (*modules[i].module_usage)();
	}
    }
}
     


void
main(
    int argc,
    char *argv[])
{
    int i;

    if (argc == 1)
	Help(NULL);

    /* initialize internals */
    trace_init();
    plot_init();

    /* let modules start first */
    LoadModules(argc,argv);

    /* parse the flags */
    ParseArgs(&argc,argv);

    printf("%d args remaining, starting with '%s'\n",
	   argc, filenames[0]);


    if (debug>1)
	DumpFlags();

    /* knock, knock... */
    printf("%s\n\n", VERSION);

    /* read each file in turn */
    for (i=0; i < argc; ++i) {
	printf("Running file '%s'\n", filenames[i]);

	/* do the real work */
	ProcessFile(filenames[i]);
    }


    /* close files, cleanup, and etc... */
    trace_done();
    FinishModules();
    plotter_done();

    exit(0);
}


static void
ProcessFile(
    char *filename)
{
    pread_f *ppread;
    int ret;
    struct ip *pip;
    int phystype;
    void *phys;  /* physical transport header */
    tcp_pair *ptp;
    int fix;
    int len;
    int tlen;
    void *plast;
    struct stat str_stat;
    long int location = 0;


    /* open the file header */
    if (CompOpenHeader(filename) == NULL) {
	exit(-1);
    }

    /* see how big the file is */
    if (stat(filename,&str_stat) != 0) {
	perror("stat");
	exit(1);
    }
    filesize = str_stat.st_size;

    /* determine which input file format it is... */
    fix = 0;
    ppread = NULL;
    while (file_formats[fix].test_func != NULL) {
	    if (debug)
                fprintf(stderr,"Checking for file format '%s' (%s)\n",
	                file_formats[fix].format_name,
	                file_formats[fix].format_descr);
	rewind(stdin);
	ppread = (*file_formats[fix].test_func)();
	if (ppread) {
	    if (debug)
                fprintf(stderr,"File format is '%s' (%s)\n",
	                file_formats[fix].format_name,
	                file_formats[fix].format_descr);
	    break;
	} else if (debug) {
	    fprintf(stderr,"File format is NOT '%s'\n",
		    file_formats[fix].format_name);
	}
	++fix;
    }

    /* if we haven't found a reader, then we can't continue */
    if (ppread == NULL) {
	fprintf(stderr,"Unknown input file format\n");
	Formats();
	exit(1);
    }

    /* open the file for processing */
    if (CompOpenFile(filename) == NULL) {
	exit(-1);
    }

    /* how big is it.... (possibly compressed) */
    if (debug) {
	/* print file size */
	printf("Trace file size: %lu bytes\n", filesize);
    }
    location = 0;

    /* inform the modules, if they care... */
    ModulesPerFile(filename);


    /* read each packet */
    while (1) {
        /* read the next packet */
	ret = (*ppread)(&current_time,&len,&tlen,&phys,&phystype,&pip,&plast);
	if (ret == 0) /* EOF */
	    break;

	++pnum;

	/* install signal handler */
	if (pnum == 1) {
	    signal(SIGINT,QuitSig);
	}


	/* progress counters */
	if (!printem && printticks) {
	    if (CompIsCompressed())
		location += tlen;  /* just guess... */
	    if (((pnum <    100) && (pnum %    10 == 0)) ||
		((pnum <   1000) && (pnum %   100 == 0)) ||
		((pnum <  10000) && (pnum %  1000 == 0)) ||
		((pnum >= 10000) && (pnum % 10000 == 0))) {

		unsigned frac;

		if (CompIsCompressed()) {
		    frac = location/(filesize/100);
		    if (frac <= 100)
			fprintf(stderr ,"%d ~%u%% (compressed)\r", pnum, frac);
		    else
			fprintf(stderr ,"%d ~100%% + %u%% (compressed)\r", pnum, frac-100);
		} else {
		    location = ftell(stdin);
		    frac = location/(filesize/100);

		    fprintf(stderr ,"%d %u%%\r", pnum, frac);
		}
	    }
	    fflush(stderr);
	}

	/* in case only a subset analysis was requested */
	if (pnum < beginpnum)	continue;
	if (pnum > endpnum)	break;


	/* quick sanity check, better be an IPv4 packet */
	if (pip->ip_v != 4) {
	    static Bool warned = FALSE;

	    if (!warned) {
		fprintf(stderr,
			"Warning: saw at least one non-v4 IP packet (vers:%d)\n",
			pip->ip_v);
		warned = TRUE;
	    }

	    if (debug)
		fprintf(stderr,
			"Skipping packet %d, not an IPv4 packet (version:%d)\n",
			pnum,pip->ip_v);
	    continue;
	}

	/* another sanity check, only understand ETHERNET right now */
	if (phystype != PHYS_ETHER) {
	    static int not_ether = 0;

	    ++not_ether;
	    if (not_ether == 5) {
		fprintf(stderr,
			"More non-ethernet packets skipped (last warning)\n");
		fprintf(stderr, "\n\
If you'll send me a trace and offer to help, I can add support\n\
for other packet types, I just don't have a place to test them\n\n");
	    } else if (not_ether < 5) {
		fprintf(stderr,
			"Skipping packet %d, not an ethernet packet\n",
			pnum);
	    } /* else, just shut up */
	    continue;
	}

	/* print the packet, if requested */
	if (printem) {
	    printf("Packet %d\n", pnum);
	    printpacket(len,tlen,phys,phystype,pip,plast);
	}

	/* we must assume it's an IP packet, but */
	/* if it's not a TCP packet, skip it */
	if (pip->ip_p != IPPROTO_TCP)
	    continue;

        /* perform packet analysis */
	ptp = dotrace(pip,plast);

	/* if it's a new connection, tell the modules */
	if (ptp->packets == 1)
	    ModulesPerConn(ptp);
	
	/* also, pass the packet to any modules defined */
	ModulesPerPacket(pip,ptp,plast);

	/* for efficiency, only allow a signal every 1000 packets	*/
	/* (otherwise the system call overhead will kill us)		*/
	if (pnum % 1000 == 0) {
	    sigset_t mask;

	    sigemptyset(&mask);
	    sigaddset(&mask,SIGINT);

	    sigprocmask(SIG_UNBLOCK, &mask, NULL);
	    /* signal can happen EXACTLY HERE, when data structures are consistant */
	    sigprocmask(SIG_BLOCK, &mask, NULL);
	}
    }

    /* set ^C back to the default */
    /* (so we can kill the output if needed) */
    {
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask,SIGINT);

	sigprocmask(SIG_UNBLOCK, &mask, NULL);
	signal(SIGINT,SIG_DFL);
    }

    /* close the input file */
    CompCloseFile(filename);
}


static void
QuitSig(
    int signum)
{
    printf("%c\n\n", 7);  /* BELL */
    printf("Terminating processing early on signal %d\n", signum);
    printf("Partial result after processing %d packets:\n\n\n", pnum);
    plotter_done();
    trace_done();
    exit(1);
}


void *
MallocZ(
  int nbytes)
{
	char *ptr;

	ptr = malloc(nbytes);
	if (ptr == NULL) {
		perror("Malloc failed, fatal\n");
		exit(2);
	}

	memset(ptr,'\00',nbytes);  /* BZERO */

	return(ptr);
}

void *
ReallocZ(
    void *oldptr,
    int obytes,
    int nbytes)
{
	char *ptr;

	ptr = realloc(oldptr,nbytes);
	if (ptr == NULL) {
		fprintf(stderr,"Realloc failed, fatal\n");
		exit(2);
	}
	if (obytes < nbytes) {
	    memset((char *)ptr+obytes,'\00',nbytes-obytes);  /* BZERO */
	}

	return(ptr);
}


static void
ParseArgs(
    int *pargc,
    char *argv[])
{
    int i;
    int saw_i_or_o = 0;

    /* parse the args */
    for (i=1; i < *pargc; ++i) {
	/* modules might have stolen args... */
	if (argv[i] == NULL)
	    continue;

	if (*argv[i] == '-') {
	    if (argv[i][1] == '\00') /* just a '-' */
		Usage(argv[0]);

	    while (*(++argv[i]))
		switch (*argv[i]) {
		  case 'C': colorplot = TRUE; break;
		  case 'D': hex = FALSE; break;
		  case 'G': graph_tput = graph_tsg = graph_rtt = TRUE; break;
		  case 'M': colorplot = FALSE; break;
		  case 'R': graph_rtt = TRUE; break;
		  case 'S': graph_tsg = TRUE; break;
		  case 'T': graph_tput = TRUE; break;
		  case 'W': print_cwin = TRUE; break;
		  case 'X': hex = TRUE; break;
		  case 'Z': dump_rtt = TRUE; break;
		  case 'b': printbrief = TRUE; break;
		  case 'c': ignore_non_comp = TRUE; break;
		  case 'e': save_tcp_data = TRUE; break;
		  case 'h': Help(argv[i]+1); *(argv[i]+1) = '\00'; break;
		  case 'l': printbrief = FALSE; break;
		  case 'n': nonames = TRUE; break;
		  case 'p': printem = TRUE; break;
		  case 'r': print_rtt = TRUE; break;
		  case 's': use_short_names = TRUE; break;
		  case 't': printticks = TRUE; break;

		  case 'd': ++debug; break;
		  case 'v': Version(); exit(0); break;
		  case 'w': printtrunc = TRUE; break;
		  case 'q': printsuppress = TRUE; break;
		  case 'z': graph_time_zero = TRUE; break;
		  case 'i':
		    ++saw_i_or_o;
		    IgnoreConn(atoi(argv[i]+1));
		    *(argv[i]+1) = '\00'; break;
		  case 'o':
		    ++saw_i_or_o;
		    OnlyConn(atoi(argv[i]+1));
		    *(argv[i]+1) = '\00'; break;
		  case 'B':
		    beginpnum = atoi(argv[i]+1);
		    *(argv[i]+1) = '\00'; break;
		  case 'E':
		    endpnum = atoi(argv[i]+1);
		    *(argv[i]+1) = '\00'; break;
		  case 'A':
		    thru_interval = atoi(argv[i]+1);
		    if (thru_interval <= 0) {
			fprintf(stderr, "-A  must be > 1\n");
			Usage(argv[0]);
		    }
		    *(argv[i]+1) = '\00'; break;
		  case 'm':
		    fprintf(stderr,
			    "-m option is obsolete (no longer necessary)\n");
		    *(argv[i]+1) = '\00'; break;
		    break;
		  case 'x':
		    fprintf(stderr,
			    "unknown module option (-x...)\n");
		    Usage(argv[0]);
		  default:
		    fprintf(stderr, "option '%c' not understood\n", *argv[i]);
		    Usage(argv[0]);
		}
	} else if (*argv[i] == '+') {
	    /* a few of them have a REVERSE flag too */
	    if (argv[i][1] == '\00') /* just a '+' */
		Usage(argv[0]);

	    while (*(++argv[i]))
		switch (*argv[i]) {
		  case 'C': colorplot = !TRUE; break;
		  case 'D': hex = !FALSE; break;
		  case 'M': colorplot = !FALSE; break;
		  case 'R': graph_rtt = !TRUE; break;
		  case 'S': graph_tsg = !TRUE; break;
		  case 'T': graph_tput = !TRUE; break;
		  case 'W': print_cwin = !TRUE; break;
		  case 'X': hex = !TRUE; break;
		  case 'Z': dump_rtt = !TRUE; break;
		  case 'b': printbrief = !TRUE; break;
		  case 'c': ignore_non_comp = !TRUE; break;
		  case 'e': save_tcp_data = FALSE; break;
		  case 'l': printbrief = !FALSE; break;
		  case 'n': nonames = !TRUE; break;
		  case 'p': printem = !TRUE; break;
		  case 'r': print_rtt = !TRUE; break;
		  case 's': use_short_names = !TRUE; break;
		  case 't': printticks = !TRUE; break;
		  case 'w': printtrunc = !TRUE; break;
		  case 'q': printsuppress = !TRUE; break;
		  case 'z': graph_time_zero = !TRUE; break;
		  default:
		    Usage(argv[0]);
		}
	} else {
	    filenames = &argv[i];
	    *pargc -= i;
	    return;
	}
    }

    /* if we got here, we didn't find a file name */
    fprintf(stderr,"must specify at least one file name\n");
    Usage(argv[0]);

    /* NOTREACHED */
}


static void
DumpFlags(void)
{
	fprintf(stderr,"printbrief:       %d\n", printbrief);
	fprintf(stderr,"printsuppress:    %d\n", printsuppress);
	fprintf(stderr,"printtrunc:       %d\n", printtrunc);
	fprintf(stderr,"print_rtt:        %d\n", print_rtt);
	fprintf(stderr,"graph tsg:        %d\n", graph_tsg);
	fprintf(stderr,"graph rtt:        %d\n", graph_rtt);
	fprintf(stderr,"graph tput:       %d\n", graph_tput);
	fprintf(stderr,"plotem:           %s\n",
	        colorplot?"(color)":"(b/w)");
	fprintf(stderr,"hex printing:     %d\n", hex);
	fprintf(stderr,"ignore_non_comp:  %d\n", ignore_non_comp);
	fprintf(stderr,"printem:          %d\n", printem);
	fprintf(stderr,"printticks:       %d\n", printticks);
	fprintf(stderr,"no names:         %d\n", nonames);
	fprintf(stderr,"use_short_names:  %d\n", use_short_names);
	fprintf(stderr,"show_rexmit:      %d\n", show_rexmit);
	fprintf(stderr,"show_zero_window: %d\n", show_zero_window);
	fprintf(stderr,"show_out_order:	  %d\n", show_out_order);
	fprintf(stderr,"save_tcp_data:    %d\n", save_tcp_data);
	fprintf(stderr,"graph_time_zero:  %d\n", graph_time_zero);
	fprintf(stderr,"beginning pnum:   %lu\n", beginpnum);
	fprintf(stderr,"ending pnum:      %lu\n", endpnum);
	fprintf(stderr,"throughput intvl: %d\n", thru_interval);
	fprintf(stderr,"number modules:   %d\n", NUM_MODULES);
	fprintf(stderr,"debug:            %d\n", debug);
}


static void
LoadModules(
    int argc,
    char *argv[])
{
    int i;
    int enable;

    for (i=0; i < NUM_MODULES; ++i) {
	++num_modules;
	if (debug)
	    fprintf(stderr,"Initializing module \"%s\"\n",
		    modules[i].module_name);
	enable = (*modules[i].module_init)(argc,argv);
	if (enable) {
	    if (debug)
		fprintf(stderr,"Module \"%s\" enabled\n",
			modules[i].module_name);
	    modules[i].module_inuse = TRUE;
	} else {
	    if (debug)
		fprintf(stderr,"Module \"%s\" not active\n",
			modules[i].module_name);
	    modules[i].module_inuse = FALSE;
	}
    }

}



static void
FinishModules(void)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_done == NULL)
	    continue;  /* might not have a cleanup */

	if (debug)
	    fprintf(stderr,"Calling cleanup for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_done)();
    }
}


static void
ModulesPerConn(
    tcp_pair *ptp)
{
    int i;
    void *pmodstruct;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_newconn == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling read routine for module \"%s\"\n",
		    modules[i].module_name);

	pmodstruct = (*modules[i].module_newconn)(ptp);
	if (pmodstruct) {
	    /* make sure the array is there */
	    if (!ptp->pmod_info) {
		ptp->pmod_info = MallocZ(num_modules * sizeof(void *));
	    }

	    /* remember this structure */
	    ptp->pmod_info[i] = pmodstruct;
	}
    }
}


static void
ModulesPerPacket(
    struct ip *pip,
    tcp_pair *ptp,
    void *plast)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (debug>3)
	    fprintf(stderr,"Calling read routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_read)(pip,ptp,plast,
				  ptp->pmod_info?ptp->pmod_info[i]:NULL);
    }
}


static void
ModulesPerFile(
    char *filename)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_newfile == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling newfile routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_newfile)(filename,filesize,CompIsCompressed());
    }
}

/* the memcpy() function that gcc likes to stuff into the program has alignment
   problems, so here's MY version.  It's only used for small stuff, so the
   copy should be "cheap", but we can't be too fancy due to alignment boo boos */
void *
MemCpy(void *vp1, void *vp2, size_t n)
{
    char *p1 = vp1;
    char *p2 = vp2;

    while (n-->0)
	*p1++=*p2++;

    return(vp1);
}

