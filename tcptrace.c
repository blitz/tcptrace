/* 
 * tcptrace.c - turn protocol monitor traces into xplot
 * 
 * Author:	Shawn Ostermann
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#include "tcptrace.h"
#include "file_formats.h"


/* version information */
char *tcptrace_version = "2.2.2 beta -- Thu Jun 22, 1995";


/* local routines */
static void Usage(char *prog);
static void Version();
static void Formats();
static void QuitSig();


/* option flags */
Bool colorplot = TRUE;
int debug = 0;
Bool hex = TRUE;
Bool ignore_non_comp = FALSE;
Bool plotem = FALSE;
Bool printbrief = FALSE;
Bool print_rtt = FALSE;
Bool dump_rtt = FALSE;
Bool printem = FALSE;
Bool printticks = FALSE;
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
    fprintf(stderr,"usage: %s  [-ncdlnprtvCDPSTX] [+bclnprtCPS] [-(BEmio)N]* file\n", prog);
    fprintf(stderr,"\
  -b      brief synopsis\n\
  -c      ignore non-complete connections\n\
  -d      enable debug\n\
  -iN     ignore connection N (can use multiple times)\n\
  -l      label rexmits, zero windows, and out-of-order when plotting\n\
  -mN     max TCP pairs to keep\n\
  -n      don't resolve host or service names (much faster)\n\
  -oN     only this connection (can use multiple times)\n\
  -p      print individual packet contents\n\
  -r      print rtt statistics\n\
  -t      'tick' off the packet numbers\n\
  -v      print version information and exit\n\
  -BN     first segment number to analyze (default 1)\n\
  -C      produce color plots (modified xplot needed)\n\
  -D      print in decimal\n\
  -EN     last segment number to analyze (default last in file)\n\
  -P      create packet trace files\n\
  -R      dump rtt samples to files\n\
  -S      use short names (list \"host.b.c\" as just \"host\")\n\
  -T      output instantaneous throughput plot files\n\
  -X      print in hexidecimal\n\
  +[v]    reverse the setting of the -[v] flag\n");
    Version();
    Formats();
    exit(-2);
}



static void
Version()
{
    fprintf(stderr,"Version: %s\n", tcptrace_version);
}


static void
Formats()
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
    int saw_i_or_o = 0;
    int len;
    int tlen;
    int i;
    int fix;
    void *phys;  /* physical transport header */
    int phystype;
    struct ip *pip;
    int ret;
    int atoi();
    Bool foundfile = FALSE;
    int (*ppread)();


    /* parse the args */
    for (i=1; i < argc; ++i) {
	if (*argv[i] == '-') {
	    if (argv[i][1] == '\00') /* just a '-' */
		Usage(argv[0]);

	    while (*(++argv[i]))
		switch (*argv[i]) {
		  case 'C': colorplot = TRUE; break;
		  case 'D': hex = FALSE; break;
		  case 'P': plotem = TRUE; break;
		  case 'X': hex = TRUE; break;
		  case 'b': printbrief = TRUE; break;
		  case 'c': ignore_non_comp = TRUE; break;
		  case 'd': ++debug; break;
		  case 'l': show_rexmit = show_out_order = show_zero_window = TRUE; break;
		  case 'n': nonames = TRUE; break;
		  case 'p': printem = TRUE; break;
		  case 'r': print_rtt = TRUE; break;
		  case 'R': dump_rtt = TRUE; break;
		  case 'T': thru_interval = 1; break;
		  case 'S': use_short_names = TRUE; break;
		  case 't': printticks = TRUE; break;
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
		  case 'b': printbrief = FALSE; break;
		  case 'c': ignore_non_comp = FALSE; break;
		  case 'l': show_rexmit = show_out_order = show_zero_window = FALSE; break;
		  case 'n': nonames = FALSE; break;
		  case 'p': printem = FALSE; break;
		  case 'r': print_rtt = FALSE; break;
		  case 'R': dump_rtt = FALSE; break;
		  case 't': printticks = FALSE; break;
		  case 'C': colorplot = FALSE; break;
		  case 'P': plotem = FALSE; break;
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

    trace_init();
    plot_init();

    if (debug>1) {
	fprintf(stderr,"debug:            %d\n", debug);
	fprintf(stderr,"ignore_non_comp:  %d\n", ignore_non_comp);
	fprintf(stderr,"plotem:           %d %s\n", plotem,
	        plotem?(colorplot?"(color)":"(b/w)"):"");
	fprintf(stderr,"printbrief:       %d\n", printbrief);
	fprintf(stderr,"printem:          %d\n", printem);
	fprintf(stderr,"printticks:       %d\n", printticks);
	fprintf(stderr,"no names:         %d\n", nonames);
	fprintf(stderr,"use_short_names:  %d\n", use_short_names);
	fprintf(stderr,"print_rtt:        %d\n", print_rtt);
	fprintf(stderr,"show_rexmit:      %d\n", show_rexmit);
	fprintf(stderr,"show_zero_window: %d\n", show_zero_window);
	fprintf(stderr,"show_out_order:	  %d\n", show_out_order);
	fprintf(stderr,"max connections:  %d\n", max_tcp_pairs);
	fprintf(stderr,"hex printing:     %d\n", hex);
	fprintf(stderr,"beginning pnum:   %lu\n", beginpnum);
	fprintf(stderr,"ending pnum:      %lu\n", endpnum);
	fprintf(stderr,"throughput intvl: %d\n", thru_interval);
    }

    if (debug) {
	struct stat stat;
	
	/* print file size */
	if (fstat(fileno(stdin),&stat) != 0) {
	    perror("fstat");
	    exit(1);
	}
	printf("Trace file size: %lu bytes\n", (u_long) stat.st_size);
	
    }


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
	
    plotter_done();
    trace_done();

    exit(0);
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

