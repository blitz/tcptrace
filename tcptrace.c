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
    "@(#)Copyright (c) 1996\nOhio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


#include "tcptrace.h"
#include "file_formats.h"
#include "version.h"


/* version information */
char *tcptrace_version = VERSION;


/* local routines */
static void ProcessFile(void);
static void DumpFlags(void);
static void Formats(void);
static void ParseArgs(int argc, char *argv[]);
static void QuitSig();
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
Bool printbrief = TRUE;
Bool printem = FALSE;
Bool printticks = FALSE;
int debug = 0;
u_long beginpnum = 0;
u_long endpnum = ~0;

/* globals */
struct timeval current_time;


/* locally global variables */
static int pnum = 0;


static void
Usage(
    char *prog)
{
    fprintf(stderr,"usage: %s [args...]* dumpfile\n", prog);
    fprintf(stderr,"\
Output format options\n\
  -b      brief output format\n\
  -l      long output format\n\
  -r      print rtt statistics (slower for large files)\n\
Graphing options\n\
  -T      create throughput graph[s], (average over 10 segments, see -A)\n\
  -R      create rtt sample graph[s]\n\
  -S      create time sequence graph[s]\n\
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
  -C      produce color plot[s] (modified xplot needed)\n\
  -M      produce monochrome (b/w) plot[s]\n\
  -AN     Average N segments for throughput graphs, default is 10\n\
Misc options\n\
  -Z      dump raw rtt sample times to file[s]\n\
  -p      print individual packet contents (can be very long)\n\
  -t      'tick' off the packet numbers as a progress indication\n\
  -mN     max TCP pairs to keep\n\
  -v      print version information and exit\n\
  -d      whistle while you work (enable debug, use -d -d for more output)\n\
  +[v]    reverse the setting of the -[v] flag (for booleans)\n\
");
    Formats();
    Version();
    exit(-2);
}



static void
Version(void)
{
    fprintf(stderr,"Version: %s\n", tcptrace_version);
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
     


void
main(
    int argc,
    char *argv[])
{

    ParseArgs(argc,argv);

    if (debug>1)
	DumpFlags();

    /* knock, knock... */
    printf("%s\n\n", VERSION);

    trace_init();
    plot_init();

    if (debug) {
	struct stat stat;
	
	/* print file size */
	if (fstat(fileno(stdin),&stat) != 0) {
	    perror("fstat");
	    exit(1);
	}
	printf("Trace file size: %lu bytes\n", (u_long) stat.st_size);
	
    }

    /* do the real work */
    ProcessFile();

    /* close files, cleanup, and etc... */
    plotter_done();
    trace_done();

    exit(0);
}


static void
ProcessFile(void)
{
    int (*ppread)();
    int ret;
    struct ip *pip;
    int phystype;
    void *phys;  /* physical transport header */
    int fix;
    int len;
    int tlen;


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


    while (1) {
        /* read the next packet */
	ret = (*ppread)(&current_time,&len,&tlen,&phys,&phystype,&pip);
	if (ret == 0) /* EOF */
	    break;

	++pnum;

	/* install signal handler */
	if (pnum == 1) {
	    signal(SIGINT,QuitSig);
	}


	/* progress counters */
	if (!printem && printticks) {
	    if ((pnum < 100) ||
		((pnum < 1000) && (pnum % 25 == 0)) ||
		((pnum < 10000) && (pnum % 100 == 0)) ||
		((pnum >= 10000) && (pnum % 1000 == 0)))
		fprintf(stderr,"%d\r", pnum);
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

	/* print the packet, if requested */
	if (printem) {
	    printf("Packet %d\n", pnum);
	    printpacket(len,tlen,phys,phystype,pip);
	}

	/* we must assume it's an IP packet, but */
	/* if it's not a TCP packet, skip it */
	if (pip->ip_p != IPPROTO_TCP)
	    continue;

        /* perform packet analysis */
	dotrace(len,pip);

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
}


void
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
	bzero(ptr,nbytes);

	return(ptr);
}


static void
ParseArgs(
    int argc,
    char *argv[])
{
    int i;
    int saw_i_or_o = 0;
    Bool foundfile = FALSE;
    
    /* parse the args */
    for (i=1; i < argc; ++i) {
	if (*argv[i] == '-') {
	    if (argv[i][1] == '\00') /* just a '-' */
		Usage(argv[0]);

	    while (*(++argv[i]))
		switch (*argv[i]) {
		  case 'C': colorplot = TRUE; break;
		  case 'D': hex = FALSE; break;
		  case 'M': colorplot = FALSE; break;
		  case 'R': graph_rtt = TRUE; break;
		  case 'S': graph_tsg = TRUE; break;
		  case 'T': graph_tput = TRUE; break;
		  case 'X': hex = TRUE; break;
		  case 'Z': dump_rtt = TRUE; break;
		  case 'b': printbrief = TRUE; break;
		  case 'c': ignore_non_comp = TRUE; break;
		  case 'l': printbrief = FALSE; break;
		  case 'n': nonames = TRUE; break;
		  case 'p': printem = TRUE; break;
		  case 'r': print_rtt = TRUE; break;
		  case 's': use_short_names = TRUE; break;
		  case 't': printticks = TRUE; break;

		  case 'd': ++debug; break;
		  case 'v': Version(); exit(0); break;
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
		    max_tcp_pairs = atoi(argv[i]+1);
		    if (max_tcp_pairs <= 0) {
			fprintf(stderr, "-m  must be > 0\n");
			Usage(argv[0]);
		    }
		    if (saw_i_or_o) {
			/* too late, the table was already made for some */
			/* other argument to work */
			fprintf(stderr, "-m MUST preceed all '-iN' and '-oM' options\n");
			Usage(argv[0]);
		    }
		    *(argv[i]+1) = '\00'; break;
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
		  case 'X': hex = !TRUE; break;
		  case 'Z': dump_rtt = !TRUE; break;
		  case 'b': printbrief = !TRUE; break;
		  case 'c': ignore_non_comp = !TRUE; break;
		  case 'l': printbrief = !FALSE; break;
		  case 'n': nonames = !TRUE; break;
		  case 'p': printem = !TRUE; break;
		  case 'r': print_rtt = !TRUE; break;
		  case 's': use_short_names = !TRUE; break;
		  case 't': printticks = !TRUE; break;
		  default:
		    Usage(argv[0]);
		}
	} else {
	    if (foundfile)
		Usage(argv[0]);
	    if (freopen(argv[i],"r",stdin) == NULL) {
		perror(argv[i]);
		exit(-1);
	    }

	    foundfile = TRUE;
	}
    }

    if (!foundfile)
	Usage(argv[0]);
}


static void
DumpFlags(void)
{
	fprintf(stderr,"printbrief:       %d\n", printbrief);
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
	fprintf(stderr,"max connections:  %d\n", max_tcp_pairs);
	fprintf(stderr,"beginning pnum:   %lu\n", beginpnum);
	fprintf(stderr,"ending pnum:      %lu\n", endpnum);
	fprintf(stderr,"throughput intvl: %d\n", thru_interval);
	fprintf(stderr,"debug:            %d\n", debug);
}
