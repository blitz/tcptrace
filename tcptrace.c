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
static char const copyright[] =
    "@(#)Copyright (c) 2001 -- Ohio University.\n";
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
static void ModulesPerNonTCPUDP(struct ip *pip, void *plast);
static void ModulesPerPacket(struct ip *pip, tcp_pair *ptp, void *plast);
static void ModulesPerUDPPacket(struct ip *pip, udp_pair *pup, void *plast);
static void ModulesPerConn(tcp_pair *ptp);
static void ModulesPerUDPConn(udp_pair *pup);
static void ModulesPerFile(char *filename);
static void DumpFlags(void);
static void ExplainOutput(void);
static void FinishModules(void);
static void Formats(void);
static void Help(char *harg);
static void Hints(void);
static void ListModules(void);
static void UsageModules(void);
static void LoadModules(int argc, char *argv[]);
static void CheckArguments(int *pargc, char *argv[]);
static void ParseArgs(char *argsource, int *pargc, char *argv[]);
static void ParseExtendedBool(char *argsource, char *arg);
static void ParseExtendedVar(char *argsource, char *arg);
static void ProcessFile(char *filename);
static void QuitSig(int signum);
static void Usage(void);
static void BadArg(char *argsource, char *format, ...);
static void Version(void);
static char *FileToBuf(char *filename);


/* option flags and default values */
Bool colorplot = TRUE;
Bool dump_rtt = FALSE;
Bool graph_rtt = FALSE;
Bool graph_tput = FALSE;
Bool graph_tsg = FALSE;
Bool graph_segsize = FALSE;
Bool graph_owin = FALSE;
Bool hex = TRUE;
Bool ignore_non_comp = FALSE;
Bool dump_packet_data = FALSE;
Bool print_rtt = FALSE;
Bool print_owin = FALSE;
Bool printbrief = TRUE;
Bool printsuppress = FALSE;
Bool printem = FALSE;
Bool printallofem = FALSE;
Bool printticks = FALSE;
Bool warn_ooo = FALSE;
Bool warn_printtrunc = FALSE;
Bool warn_printbadmbz = FALSE;
Bool warn_printhwdups = FALSE;
Bool warn_printbadcsum = FALSE;
Bool warn_printbad_syn_fin_seq = FALSE;
Bool docheck_hw_dups = TRUE;
Bool save_tcp_data = FALSE;
Bool graph_time_zero = FALSE;
Bool graph_seq_zero = FALSE;
Bool graph_zero_len_pkts = TRUE;
Bool plot_tput_instant = TRUE;
Bool filter_output = FALSE;
Bool show_title = TRUE;
Bool do_udp = FALSE;
Bool resolve_ipaddresses = TRUE;
Bool resolve_ports = TRUE;
Bool verify_checksums = FALSE;
Bool triple_dupack_allows_data = FALSE;
Bool run_continuously = FALSE;
Bool xplot_all_files = FALSE;
Bool conn_num_threshold = FALSE;
u_long remove_live_conn_interval = REMOVE_LIVE_CONN_INTERVAL;
u_long remove_closed_conn_interval = REMOVE_CLOSED_CONN_INTERVAL;
u_long update_interval = UPDATE_INTERVAL;
u_long max_conn_num = MAX_CONN_NUM;
int debug = 0;
u_long beginpnum = 0;
u_long endpnum = 0;
u_long pnum = 0;
u_long ctrunc = 0;
u_long bad_ip_checksums = 0;
u_long bad_tcp_checksums = 0;
u_long bad_udp_checksums = 0;

/* extended variables with values */
char *output_file_dir = NULL;
char *output_file_prefix = NULL;
char *xplot_title_prefix = NULL;
char *xplot_args = NULL;
/* globals */
struct timeval current_time;
int num_modules = 0;
char *ColorNames[NCOLORS] =
{"green", "red", "blue", "yellow", "purple", "orange", "magenta", "pink"};


/* locally global variables */
static u_long filesize = 0;
char **filenames = NULL;
int num_files = 0;
u_int numfiles;
char *cur_filename;
static char *progname;
char *output_filename = NULL;
static char *update_interval_st = NULL;
static char *max_conn_num_st = NULL;
static char *live_conn_interval_st = NULL;
static char *closed_conn_interval_st = NULL;

/* for elapsed processing time */
struct timeval wallclock_start;
struct timeval wallclock_finished;


/* first and last packet timestamp */
timeval first_packet = {0,0};
timeval last_packet = {0,0};


/* extended boolean options */
static struct ext_bool_op {
    char *bool_optname;
    Bool *bool_popt;
    Bool bool_default;
    char *bool_descr;
} extended_bools[] = {
    {"showsacks", &show_sacks,  TRUE,
     "show SACK blocks on time sequence graphs"},
    {"showrexmit", &show_rexmit,  TRUE,
     "mark retransmits on time sequence graphs"},
    {"showoutorder", &show_out_order,  TRUE,
     "mark out-of-order on time sequence graphs"},
    {"showzerowindow", &show_zero_window,  TRUE,
     "mark zero windows on time sequence graphs"},
    {"showurg", &show_urg,  TRUE,
     "mark packets with URGENT bit set on the time sequence graphs"},
    {"showrttdongles", &show_rtt_dongles,  TRUE,
     "mark non-RTT-generating ACKs with special symbols"},
    {"showdupack3", &show_triple_dupack,  TRUE,
     "mark triple dupacks on time sequence graphs"},
    {"showzerolensegs", &graph_zero_len_pkts,  TRUE,
     "show zero length packets on time sequence graphs"},
	{"showzwndprobes", &show_zwnd_probes, TRUE,
	 "show zero window probe packets on time sequence graphs"},
    {"showtitle", &show_title,  TRUE,
     "show title on the graphs"},
    {"res_addr", &resolve_ipaddresses,  TRUE,
     "resolve IP addresses into names (may be slow)"},
    {"res_port", &resolve_ports,  TRUE,
     "resolve port numbers into names"},
    {"checksum", &verify_checksums,  TRUE,
     "verify IP and TCP checksums"},
    {"dupack3_data", &triple_dupack_allows_data, TRUE,
     "count a duplicate ACK carrying data as a triple dupack"},
    {"check_hwdups", &docheck_hw_dups, TRUE,
     "check for 'hardware' dups"},
    {"warn_ooo", &warn_ooo,  TRUE,
     "print warnings when packets timestamps are out of order"},
    {"warn_printtrunc", &warn_printtrunc,  TRUE,
     "print warnings when packets are too short to analyze"},
    {"warn_printbadmbz", &warn_printbadmbz, TRUE,
     "print warnings when MustBeZero TCP fields are NOT 0"},
    {"warn_printhwdups", &warn_printhwdups, TRUE,
     "print warnings for hardware duplicates"},
    {"warn_printbadcsum", &warn_printbadcsum, TRUE,
     "print warnings when packets with bad checksums"},
    {"warn_printbad_syn_fin_seq", &warn_printbad_syn_fin_seq, TRUE,
     "print warnings when SYNs or FINs rexmitted with different sequence numbers"},
    {"dump_packet_data", &dump_packet_data, TRUE,
     "print all packets AND dump the TCP/UDP data"},
    {"continuous", &run_continuously, TRUE,
     "run continuously and don't provide a summary"},
    {"limit_conn_num", &conn_num_threshold, TRUE,
     "limit the maximum number of connections kept at a time in real-time mode"},
	{"xplot_all_files", &xplot_all_files, TRUE,
	 "display all generated xplot files at the end"},

};
#define NUM_EXTENDED_BOOLS (sizeof(extended_bools) / sizeof(struct ext_bool_op))


/* extended variable verification routines */
static u_long VerifyPositive(char *varname, char *value);
static void VerifyUpdateInt(char *varname, char *value);
static void VerifyMaxConnNum(char *varname, char *value);
static void VerifyLiveConnInt(char *varname, char *value);
static void VerifyClosedConnInt(char *varname, char *value);

/* extended variable options */
/* they must all be strings */
static struct ext_var_op {
    char *var_optname;		/* what it's called when you set it */
    char **var_popt;		/* the variable itself */
    void (*var_verify)(char *varname,
		       char *value);
				/* function to call to verify that the
				   value is OK (if non-null) */
    char *var_descr;		/* variable description */
} extended_vars[] = {
    {"output_dir", &output_file_dir, NULL,
     "directory where all output files are placed"},
    {"output_prefix", &output_file_prefix, NULL,
     "prefix all output files with this string"},
    {"xplot_title_prefix", &xplot_title_prefix, NULL,
     "prefix to place in the titles of all xplot files"},
    {"update_interval", &update_interval_st, VerifyUpdateInt,
     "time interval for updates in real-time mode"},
    {"max_conn_num", &max_conn_num_st, VerifyMaxConnNum,
     "maximum number of connections to keep at a time in real-time mode"},
    {"remove_live_conn_interval", &live_conn_interval_st, VerifyLiveConnInt,
     "idle time after which an open connection is removed in real-time mode"},
    {"remove_closed_conn_interval", &closed_conn_interval_st, VerifyClosedConnInt,
     "time interval after which a closed connection is removed in real-time mode"},
	{"xplot_args", &xplot_args, NULL,
	 "arguments to pass to xplot, if we are calling xplot from here"},
};
#define NUM_EXTENDED_VARS (sizeof(extended_vars) / sizeof(struct ext_var_op))

static void
Help(
    char *harg)
{
    if (harg && *harg && strncmp(harg,"arg",3) == 0) {
	Args();
    } else if (harg && *harg && strncmp(harg,"xarg",3) == 0) {
	UsageModules();
    } else if (harg && *harg && strncmp(harg,"filt",4) == 0) {
	HelpFilter();
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
  -hxargs   tell me about the module arguments  \n\
  -hconfig  tell me about the configuration of this binary  \n\
  -houtput  explain what the output means  \n\
  -hfilter  output filtering help  \n\
  -hhints   usage hints  \n");
    }

    fprintf(stderr,"\n");
    Version();
    exit(0);
}



static void
BadArg(
    char *argsource,
    char *format,
    ...)
{
    va_list ap;

    fprintf(stderr,"Argument error");
    if (argsource)
	fprintf(stderr," (from %s)", argsource);
    fprintf(stderr,": ");
    
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    va_end(ap);
    
    Usage();
}



static void
Usage(void)
{
    fprintf(stderr,"usage: %s [args...]* dumpfile [more files]*\n",
	    progname);

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
If you're graphing results and only want the information for a few conns,\n\
   from a large file, use the -o flag, as in \"tcptrace -o3,4,5 -o8-11\" to\n\
   only process connections 3,4,5, and 8 through 11.\n\
   Alternately, the '-oFILE' option allows you to write the connection\n\
   list into a file using some other program (or the file PF from -f)\n\
Make sure the snap length in the packet grabber is big enough.\n\
     Ethernet headers are 14 bytes, as are several others\n\
     IPv4 headers are at least 20 bytes, but can be as large as 64 bytes\n\
     TCP headers are at least 20 bytes, but can be as large as 64 bytes\n\
   Therefore, if you want to be SURE that you see all of the options,\n\
   make sure that you set the snap length to 14+64+64=142 bytes.  If\n\
   I'm not sure, I usually use 128 bytes.  If you're SURE that there are no\n\
   options (TCP usually has some), you still need at least 54 bytes.\n\
Compress trace files using gzip, I can uncompress them on the fly\n\
Stuff arguments that you always use into either the tcptrace resource file\n\
   ($HOME/%s) or the envariable %s.  If you need to turn\n\
   them off again from the command line, you can use\n\
   the \"+\" option flag.\n\
", TCPTRACE_RC_FILE, TCPTRACE_ENVARIABLE);
}


static void
Args(void)
{
    int i;
    
    fprintf(stderr,"\n\
Note: these options are first read from the file $HOME/%s\n\
  (if it exists), and then from the environment variable %s\n\
  (if it exists), and finally from the command line\n\
", TCPTRACE_RC_FILE, TCPTRACE_ENVARIABLE);
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
  -N      create owin graph[s] (_o_utstanding data on _N_etwork)\n\
  -F      create segsize graph[s]\n\
  -G	  create ALL graphs\n\
Output format detail options\n\
  -D      print in decimal\n\
  -X      print in hexidecimal\n\
  -n      don't resolve host or service names (much faster)\n\
  -s      use short names (list \"picard.cs.ohiou.edu\" as just \"picard\")\n\
Connection filtering options\n\
  -iN     ignore connection N (can use multiple times)\n\
  -oN[-M] only connection N (or N through M).  Arg can be used many times.\n\
          In N is a file rather than a number, read list from file instead.\n\
  -c      ignore non-complete connections (didn't see syn's and fin's)\n\
  -BN     first segment number to analyze (default 1)\n\
  -EN     last segment number to analyze (default last in file)\n\
Graphing detail options\n\
  -C      produce color plot[s]\n\
  -M      produce monochrome (b/w) plot[s]\n\
  -AN     Average N segments for throughput graphs, default is 10\n\
  -z      zero axis options\n\
    -z      plot time axis from 0 rather than wall clock time (backward compat)\n\
    -zx     plot time axis from 0 rather than wall clock time\n\
    -zy     plot sequence numbers from 0 (time sequence graphs only)\n\
    -zxy    plot both axes from 0\n\
  -y      omit the (yellow) instantaneous throughput points in tput graph\n\
Misc options\n\
  -Z      dump raw rtt sample times to file[s]\n\
  -p      print all packet contents (can be very long)\n\
  -P      print packet contents for selected connections\n\
  -t      'tick' off the packet numbers as a progress indication\n\
  -fEXPR  output filtering (see -hfilter)\n\
  -v      print version information and exit\n\
  -w      print various warning messages\n\
  -d      whistle while you work (enable debug, use -d -d for more output)\n\
  -e      extract contents of each TCP stream into file\n\
  -h      print help messages\n\
  -u      perform (minimal) UDP analysis too\n\
  -Ofile  dump matched packets to tcpdump file 'file'\n\
  +[v]    reverse the setting of the -[v] flag (for booleans)\n\
Dump File Names\n\
  Anything else in the arguments is taken to be one or more filenames.\n\
  The files can be compressed, see compress.h for configuration.\n\
  If the dump file name is 'stdin', then we read from standard input\n\
    rather than from a file\n\
");

    fprintf(stderr,"\nExtended boolean options\n");
    fprintf(stderr," (unambiguous prefixes also work)\n");
    for (i=0; i < NUM_EXTENDED_BOOLS; ++i) {
	struct ext_bool_op *pbop = &extended_bools[i];
	fprintf(stderr,"  --%-20s %s %s\n",
		pbop->bool_optname, pbop->bool_descr,
		(*pbop->bool_popt == pbop->bool_default)?"(default)":"");
	fprintf(stderr,"  --no%-18s DON'T %s %s\n",
		pbop->bool_optname, pbop->bool_descr,
		(*pbop->bool_popt != pbop->bool_default)?"(default)":"");
    }

    fprintf(stderr,"\nExtended variable options\n");
    fprintf(stderr," (unambiguous prefixes also work)\n");
    for (i=0; i < NUM_EXTENDED_VARS; ++i) {
	char buf[256];		/* plenty large, but checked below with strncpy */
	struct ext_var_op *pvop = &extended_vars[i];
	strncpy(buf,pvop->var_optname,sizeof(buf)-10);
	strcat(buf,"=\"STR\"");
	fprintf(stderr,"  --%-20s %s (default: '%s')\n",
		buf,
		pvop->var_descr,
		(*pvop->var_popt)?*pvop->var_popt:"<NULL>");
    }

    fprintf(stderr,"\n\
Module options\n\
  -xMODULE_SPECIFIC  (see -hxargs for details)\n\
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
    for (i=0; i < NUM_FILE_FORMATS; ++i)
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
/* 	if (modules[i].module_usage) { */
/* 	    fprintf(stderr,"    usage:\n"); */
/* 	    (*modules[i].module_usage)(); */
/* 	} */
    }
}


static void
UsageModules(void)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	fprintf(stderr," Module %s:\n", modules[i].module_name);
	if (modules[i].module_usage) {
	    fprintf(stderr,"    usage:\n");
	    (*modules[i].module_usage)();
	}
    }
}
     


int
main(
    int argc,
    char *argv[])
{
    int i;
    double etime;

    if (argc == 1)
	Help(NULL);

    /* initialize internals */
    trace_init();
    plot_init();

    /* let modules start first */
    LoadModules(argc,argv);

    /* parse the flags */
    CheckArguments(&argc,argv);

    /* optional UDP */
    if (do_udp)
	udptrace_init();

    if (run_continuously) {
      trace_init();
    }

    /* get starting wallclock time */
    gettimeofday(&wallclock_start, NULL);

    num_files = argc;
    printf("%d arg%s remaining, starting with '%s'\n",
	   num_files,
	   num_files>1?"s":"",
	   filenames[0]);
    


    if (debug>1)
	DumpFlags();

    /* knock, knock... */
    printf("%s\n\n", VERSION);

    /* read each file in turn */
    numfiles = argc;
    for (i=0; i < argc; ++i) {
	if (debug || (numfiles > 1)) {
	    if (argc > 1)
		printf("Running file '%s' (%d of %d)\n", filenames[i], i+1, numfiles);
	    else
		printf("Running file '%s'\n", filenames[i]);
	}

	/* do the real work */
	ProcessFile(filenames[i]);
    }

    /* clean up output */
    if (printticks)
	printf("\n");

    /* get ending wallclock time */
    gettimeofday(&wallclock_finished, NULL);

    /* general output */
    fprintf(stdout, "%lu packets seen, %lu TCP packets traced",
	    pnum, tcp_trace_count);
    if (do_udp)
	fprintf(stdout,", %lu UDP packets traced", udp_trace_count);
    fprintf(stdout,"\n");

    /* processing time */
    etime = elapsed(wallclock_start,wallclock_finished);
    fprintf(stdout, "elapsed wallclock time: %s, %d pkts/sec analyzed\n",
	    elapsed2str(etime),
	    (int)((double)pnum/(etime/1000000)));

    /* actual tracefile times */
    etime = elapsed(first_packet,last_packet);
    fprintf(stdout,"trace %s elapsed time: %s\n",
	    (num_files==1)?"file":"files",
	    elapsed2str(etime));
    if (debug) {
	fprintf(stdout,"\tfirst packet:  %s\n", ts2ascii(&first_packet));
	fprintf(stdout,"\tlast packet:   %s\n", ts2ascii(&last_packet));
    }
    if (verify_checksums) {
	fprintf(stdout,"bad IP checksums:  %ld\n", bad_ip_checksums);
	fprintf(stdout,"bad TCP checksums: %ld\n", bad_tcp_checksums);
	if (do_udp)
	    fprintf(stdout,"bad UDP checksums: %ld\n", bad_udp_checksums);
    }

    /* close files, cleanup, and etc... */
    trace_done();
    if (!run_continuously) {
      /* countinuos mode is not supported for udp */
      if (do_udp)
	udptrace_done();
    }
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
    struct tcphdr *ptcp;
    int phystype;
    void *phys;  /* physical transport header */
    tcp_pair *ptp;
    int fix;
    int len;
    int tlen;
    void *plast;
    struct stat str_stat;
    long int location = 0;
    u_long fpnum = 0;
    Bool is_stdin = 0;
    static int file_count = 0;

    /* share the current file name */
    cur_filename = filename;

    /* open the file header */
    if (CompOpenHeader(filename) == NULL) {
	exit(-1);
    }

    /* see how big the file is */
    if (FileIsStdin(filename)) {
	filesize = 1;
	is_stdin = 1;
    } else {
	if (stat(filename,&str_stat) != 0) {
	    perror("stat");
	    exit(1);
	}
	filesize = str_stat.st_size;
    }

    /* determine which input file format it is... */
    ppread = NULL;
    if (debug>1)
	printf("NUM_FILE_FORMATS: %u\n", (unsigned)NUM_FILE_FORMATS);
    for (fix=0; fix < NUM_FILE_FORMATS; ++fix) {
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
    }

    /* if we haven't found a reader, then we can't continue */
    if (ppread == NULL) {
	int count = 0;

	fprintf(stderr,"Unknown input file format\n");
	Formats();

	/* check for ASCII, a common problem */
	rewind(stdin);
	while (1) {
	    int ch;
	    if ((ch = getchar()) == EOF)
		break;
	    if (!isprint(ch))
		break;
	    if (++count >= 20) {
		/* first 20 are all ASCII */
		fprintf(stderr,"\
\n\nHmmmm.... this sure looks like an ASCII input file to me.\n\
The first %d characters are all printable ASCII characters. All of the\n\
packet grabbing formats that I understand output BINARY files that I\n\
like to read.  Could it be that you've tried to give me the readable \n\
output instead?  For example, with tcpdump, you need to use:\n\
\t tcpdump -w outfile.dmp ; tcptrace outfile.dmp\n\
rather than:\n\
\t tcpdump > outfile ; tcptrace outfile\n\n\
", count);
		exit(1);
	    }
	}
	
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

    /* count the files */
    ++file_count;


    /* read each packet */
    while (1) {
        /* read the next packet */
	ret = (*ppread)(&current_time,&len,&tlen,&phys,&phystype,&pip,&plast);
	if (ret == 0) /* EOF */
	    break;

	/* update global and per-file packet counters */
	++pnum;			/* global */
	++fpnum;		/* local to this file */


	/* in case only a subset analysis was requested */
	if (pnum < beginpnum)	continue;
	if ((endpnum != 0) && (pnum > endpnum))	{
	    --pnum;
	    --fpnum;
	    break;
	    }


	/* check for re-ordered packets */
	if (!ZERO_TIME(&last_packet)) {
	    if (elapsed(last_packet , current_time) < 0) {
		/* out of order */
		if ((file_count > 1) && (fpnum == 1)) {
		    fprintf(stderr, "\
Warning, first packet in file %s comes BEFORE the last packet\n\
in the previous file.  That will likely confuse the program, please\n\
order the files in time if you have trouble\n", filename);
		} else {
		    static int warned = 0;

		    if (warn_ooo) {
			fprintf(stderr, "\
Warning, packet %ld in file %s comes BEFORE the previous packet\n\
That will likely confuse the program, so be careful!\n",
				fpnum, filename);
		    } else if (!warned) {
			fprintf(stderr, "\
Packets in file %s are out of order.\n\
That will likely confuse the program, so be careful!\n", filename);
		    }
		    warned = 1;
		}

	    }
	}
	

	/* install signal handler */
	if (fpnum == 1) {
	    signal(SIGINT,QuitSig);
	}


	/* progress counters */
	if (!printem && !printallofem && printticks) {
	    if (CompIsCompressed())
		location += tlen;  /* just guess... */
	    if (((fpnum <    100) && (fpnum %    10 == 0)) ||
		((fpnum <   1000) && (fpnum %   100 == 0)) ||
		((fpnum <  10000) && (fpnum %  1000 == 0)) ||
		((fpnum >= 10000) && (fpnum % 10000 == 0))) {

		unsigned frac;

		if (debug)
		    fprintf(stderr, "%s: ", cur_filename);
		if (is_stdin) {
		    fprintf(stderr ,"%lu", fpnum);
		} else if (CompIsCompressed()) {
		    frac = location/(filesize/100);
		    if (frac <= 100)
			fprintf(stderr ,"%lu ~%u%% (compressed)", fpnum, frac);
		    else
			fprintf(stderr ,"%lu ~100%% + %u%% (compressed)", fpnum, frac-100);
		} else {
		    location = ftell(stdin);
		    frac = location/(filesize/100);

		    fprintf(stderr ,"%lu %u%%", fpnum, frac);
		}
		/* print elapsed time */
		{
		    double etime = elapsed(first_packet,last_packet);
		    fprintf(stderr," (%s)", elapsed2str(etime));
		}

		/* carriage return (but not newline) */
		fprintf(stderr ,"\r");
	    }
	    fflush(stderr);
	}


	/* quick sanity check, better be an IPv4/v6 packet */
	if (!PIP_ISV4(pip) && !PIP_ISV6(pip)) {
	    static Bool warned = FALSE;

	    if (!warned) {
		fprintf(stderr,
			"Warning: saw at least one non-ip packet\n");
		warned = TRUE;
	    }

	    if (debug)
		fprintf(stderr,
			"Skipping packet %lu, not an IPv4/v6 packet (version:%d)\n",
			pnum,IP_V(pip));
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
			"Skipping packet %lu, not an ethernet packet\n",
			pnum);
	    } /* else, just shut up */
	    continue;
	}

	/* print the packet, if requested */
	if (printallofem || dump_packet_data) {
	    printf("Packet %lu\n", pnum);
	    printpacket(len,tlen,phys,phystype,pip,plast);
	}

	/* keep track of global times */
	if (ZERO_TIME(&first_packet))
	    first_packet = current_time;
	last_packet = current_time;

	/* verify IP checksums, if requested */
	if (verify_checksums) {
	    if (!ip_cksum_valid(pip,plast)) {
		++bad_ip_checksums;
		if (warn_printbadcsum)
		    fprintf(stderr, "packet %lu: bad IP checksum\n", pnum);
		continue;
	    }
	}
		       
	/* find the start of the TCP header */
	ret = gettcp (pip, &ptcp, &plast);

	/* if that failed, it's not TCP */
	if (ret < 0) {
	    udp_pair *pup;
	    struct udphdr *pudp;

	    /* look for a UDP header */
	    ret = getudp(pip, &pudp, &plast);

	    if (do_udp && (ret == 0)) {
		pup = udpdotrace(pip,pudp,plast);

		/* verify UDP checksums, if requested */
		if (verify_checksums) {
		    if (!udp_cksum_valid(pip,pudp,plast)) {
			++bad_udp_checksums;
			if (warn_printbadcsum)
			    fprintf(stderr, "packet %lu: bad UDP checksum\n",
				    pnum);
			continue;
		    }
		}
		       
		/* if it's a new connection, tell the modules */
		if (pup && pup->packets == 1)
		    ModulesPerUDPConn(pup);
		/* also, pass the packet to any modules defined */
		ModulesPerUDPPacket(pip,pup,plast);
	    } else if (ret < 0) {
		/* neither UDP not TCP */
		ModulesPerNonTCPUDP(pip,plast);
	    }
	    continue;
	}
        else if (ret > 0) { /* not a valid TCP packet */
	  continue;
        }

	/* verify TCP checksums, if requested */
	if (verify_checksums) {
	    if (!tcp_cksum_valid(pip,ptcp,plast)) {
		++bad_tcp_checksums;
		if (warn_printbadcsum) 
		    fprintf(stderr, "packet %lu: bad TCP checksum\n", pnum);
		continue;
	    }
	}
		       
        /* perform TCP packet analysis */
	ptp = dotrace(pip,ptcp,plast);

	/* if it wasn't "interesting", we return NULL here */
	if (ptp == NULL)
	    continue;

	/* unless this connection is being ignored, tell the modules */
	/* about it */
	if (!ptp->ignore_pair) {
	    /* if it's a new connection, tell the modules */
	    if (ptp->packets == 1)
		ModulesPerConn(ptp);

	    /* also, pass the packet to any modules defined */
	    ModulesPerPacket(pip,ptp,plast);
	}

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
    printf("Partial result after processing %lu packets:\n\n\n", pnum);
    FinishModules();
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
		fprintf(stderr,"\
when memory allocation fails, it's either because:\n\
1) You're out of swap space, talk to your local sysadmin about making more\n\
   (look for system commands 'swap' or 'swapon' for quick fixes)\n\
2) The amount of memory that your OS gives each process is too little\n\
   That's a system configuration issue that you'll need to discuss\n\
   with the system administrator\n\
");
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
		fprintf(stderr,
			"Realloc failed (%d bytes --> %d bytes), fatal\n",
			obytes, nbytes);
		perror("realloc");
		exit(2);
	}
	if (obytes < nbytes) {
	    memset((char *)ptr+obytes,'\00',nbytes-obytes);  /* BZERO */
	}

	return(ptr);
}

static void
GrabOnly(
    char *argsource,
    char *opt)
{
    char *o_arg;
		      
    /* next part of arg is a filename or number list */
    if (*opt == '\00') {
	BadArg(argsource,"Expected filename or number list\n");
    }

    /* option is a list of connection numbers separated by commas */
    /* option can be immediately "here" or given as a file name */
    if (isdigit((int)(*opt))) {
	/* list is on the command line */
	o_arg = opt;
    } else {
	/* it's in a file */

	/* open the file */
	o_arg = FileToBuf(opt);

	/* if that fails, it's a command line error */
	if (o_arg == NULL) {
	    Usage();
	}
    }

    /* wherever we got it, o_arg is a connection list */
    while (o_arg && *o_arg) {
	int num1,num2;
	
	if (sscanf(o_arg,"%d-%d",&num1,&num2) == 2) {
	    /* process range */
	    if (num2 <= num1) {
		BadArg(argsource,
		       "-oX-Y, must have X<Y, '%s'\n", o_arg);
	    }
	    if (debug)
		printf("setting OnlyConn(%d-%d)\n", num1, num2);

	    while (num1<=num2) {
		if (debug > 1)
		    printf("setting OnlyConn(%d)\n", num1);
		OnlyConn(num1++);
	    }
	} else if (sscanf(o_arg,"%d",&num1) == 1) {
	    /* single argument */
	    if (debug)
		printf("setting OnlyConn(%d)\n", num1);
	    OnlyConn(num1);
	} else {
	    /* error */
	    BadArg(argsource,
		   "Don't understand conn number starting at '%s'\n", o_arg);
	}
		   
	/* look for the next comma */
	o_arg = strchr(o_arg,',');
	if (o_arg)
	    ++o_arg;
    }
}


/* convert a buffer to an argc,argv[] pair */
void
StringToArgv(
    char *buf,
    int *pargc,
    char ***pargv)
{
    char **argv;
    int nargs = 0;

    /* discard the original string, use a copy */
    buf = strdup(buf);

    /* (very pessimistically) make the argv array */
    argv = malloc(sizeof(char *) * ((strlen(buf)/2)+1));

    /* skip leading blanks */
    while ((*buf != '\00') && (isspace((int)*buf))) {
	if (debug > 10)
	    printf("skipping isspace('%c')\n", *buf);	    
	++buf;
    }

    /* break into args */
    for (nargs = 1; *buf != '\00'; ++nargs) {
	char *stringend;
	argv[nargs] = buf;

	/* search for separator */
	while ((*buf != '\00') && (!isspace((int)*buf))) {
	    if (debug > 10)
		printf("'%c' (%d) is NOT a space\n", *buf, (int)*buf);	    
	    ++buf;
	}
	stringend = buf;

	/* skip spaces */
	while ((*buf != '\00') && (isspace((int)*buf))) {
	    if (debug > 10)
		printf("'%c' (%d) IS a space\n", *buf, (int)*buf);	    
	    ++buf;
	}

	*stringend = '\00';  /* terminate the previous string */

	if (debug)
	    printf("  argv[%d] = '%s'\n", nargs, argv[nargs]);
    }

    *pargc = nargs;
    *pargv = argv;
}


static void
CheckArguments(
    int *pargc,
    char *argv[])
{
    char *home;
    char *envariable;
    char *rc_path = NULL;
    char *rc_buf = NULL;

    /* remember the name of the program for errors... */
    progname = argv[0];

    /* first, we read from the config file, "~/.tcptracerc" */
    if ((home = getenv("HOME")) != NULL) {
	struct stat statbuf;

	int rc_len=strlen(home)+strlen(TCPTRACE_RC_FILE)+2;

	rc_path = malloc(rc_len);

	snprintf(rc_path,rc_len, "%s/%s", home, TCPTRACE_RC_FILE);
	if (debug>1)
	    printf("Looking for resource file '%s'\n", rc_path);

	if (stat(rc_path,&statbuf) != 0) {
	    rc_path = NULL;
	} else {
	    int argc;
	    char **argv;
	    char *pch_file;
	    char *pch_new;
	    char *file_buf;

	    if (debug>1)
		printf("resource file %s exists\n", rc_path);

	    /* read the file into a buffer */
	    rc_buf = file_buf = FileToBuf(rc_path);

	    /* if it exists but can't be read, that's a fatal error */
	    if (rc_buf == NULL) {
		fprintf(stderr,
			"Couldn't read resource file '%s'\n", rc_path);
		fprintf(stderr,
			"(either make the file readable or change its name)\n");
		exit(-1);
	    }
	    

	    /* make a new buffer to hold the converted string */
	    pch_file = rc_buf;
	    rc_buf = pch_new = MallocZ(strlen(file_buf)+3);

	    /* loop until end of string */
	    while (*pch_file) {
		if (*pch_file == '\n') {
		    /* turn newlines into spaces */
		    *pch_new++ = ' ';
		    ++pch_file;
		} else if (*pch_file == '#') {
		    /* skip over the '#' */
		    ++pch_file;

		    /* remove comments (until NULL or newline) */
		    while ((*pch_file != '\00') &&
			   (*pch_file != '\n')) {
			++pch_file;
		    }
		    /* insert a space */
		    *pch_new++ = ' ';
		} else {
		    /* just copy the characters */
		    *pch_new++ = *pch_file++;
		}
	    }

	    /* append a NULL to pch_new */
	    *pch_new = '\00';

	    if (debug>2)
		printf("Resource file string: '%s'\n", rc_buf);

	    /* we're finished with the original buffer, but need to keep pch_new */
	    free(file_buf);

	    /* parse those args */
	    StringToArgv(rc_buf,&argc,&argv);
	    ParseArgs(TCPTRACE_RC_FILE, &argc, argv);
	}
    }

    /* next, we read from the environment variable "TCPTRACEOPTS" */
    if ((envariable = getenv(TCPTRACE_ENVARIABLE)) != NULL) {
	int argc;
	char **argv;

	if (debug)
	    printf("envariable %s contains:\n\t'%s'\n",
		   TCPTRACE_ENVARIABLE, envariable);

	StringToArgv(envariable,&argc,&argv);
	ParseArgs(TCPTRACE_ENVARIABLE, &argc, argv);
    }

    /* lastly, we read the command line arguments */
    ParseArgs("command line",pargc,argv);

    /* make sure we found the files */
    if (filenames == NULL) {
	BadArg(NULL,"must specify at least one file name\n");
    }

    /* if debugging is on, tell what was in the ENV and rc file */
    if (debug) {
	if (rc_path)
	    printf("Flags from %s: '%s'\n", rc_path, rc_buf);
	if (envariable)
	    printf("envariable %s contains: '%s'\n",
		   TCPTRACE_ENVARIABLE, envariable);
    }

    if (rc_buf)
	free(rc_buf);

    /* heuristic, I set "-t" in my config file, but they don't work inside */
    /* emacs shell windows, which is a pain.  If the terminal looks like EMACS, */
    /* then turn OFF ticks! */
    if (printticks) {
	char *TERM = getenv("TERM");
	/* allow emacs and Emacs */
	if ((TERM != NULL) && 
	    ((strstr(TERM,"emacs") != NULL) ||
	     (strstr(TERM,"Emacs") != NULL))) {
	    printf("Disabling ticks for EMACS shell window\n");
	    printticks = 0;
	}
    }
}




/* these extended boolean options are table driven, to make it easier to
   add more later without messing them up */
static void
ParseExtendedBool(
    char *argsource,
    char *arg)
{
    int i;
    struct ext_bool_op *pbop_found = NULL;
    struct ext_bool_op *pbop_prefix = NULL;
    Bool prefix_ambig = FALSE;
    Bool negative_arg_prefix;
    char *argtext;
    int arglen;

    /* there must be at least SOME text there */
    if ((strcmp(arg,"--") == 0) || (strcmp(arg,"--no") == 0))
	BadArg(argsource, "Void extended boolean argument\n");

    /* find just the arg text */
    if (strncmp(arg,"--no",4) == 0) {
	argtext = arg+4;
	negative_arg_prefix = TRUE;
    } else {
	argtext = arg+2;
	negative_arg_prefix = FALSE;
    }
    arglen = strlen(argtext);


    /* search for a match on each extended boolean arg */
    for (i=0; i < NUM_EXTENDED_BOOLS; ++i) {
	struct ext_bool_op *pbop = &extended_bools[i];

	/* check for the default value flag */
	if (strcmp(argtext,pbop->bool_optname) == 0) {
	    pbop_found = pbop;
	    break;
	}

	/* check for a prefix match */
	if (strncmp(argtext,pbop->bool_optname,arglen) == 0) {
	    if (pbop_prefix == NULL)
		pbop_prefix = pbop;
	    else
		prefix_ambig = TRUE;
	}
    }


    /* if we never found a match, it's an error */
    if ((pbop_found == NULL) && (pbop_prefix == NULL))
	BadArg(argsource, "Unknown extended boolean argument '%s' (see -hargs)\n", arg);


    /* if the prefix is UNambiguous, that's good enough */
    if ((pbop_prefix != NULL) && (!prefix_ambig))
	pbop_found = pbop_prefix;

    /* either exact match or good prefix, do it */
    if (pbop_found != NULL) {
	if (negative_arg_prefix)
	    *pbop_found->bool_popt = !pbop_found->bool_default;
	else
	    *pbop_found->bool_popt = pbop_found->bool_default;
	if (debug>2)
	    fprintf(stderr,"Set boolean variable '%s' to '%s'\n",
		    argtext, BOOL2STR(*pbop_found->bool_popt));
	return;
    }

    /* ... else ambiguous prefix */
    fprintf(stderr,"Extended boolean arg '%s' is ambiguous, it matches:\n", arg);
    for (i=0; i < NUM_EXTENDED_BOOLS; ++i) {
	struct ext_bool_op *pbop = &extended_bools[i];
	if (strncmp(argtext,pbop->bool_optname,arglen) == 0)
	    fprintf(stderr,"  %s%s - %s%s\n",
		    negative_arg_prefix?"no":"",
		    pbop->bool_optname,
		    negative_arg_prefix?"DON'T ":"",
		    pbop->bool_descr);
    }
    BadArg(argsource, "Ambiguous extended argument '%s'\n", arg);
    
    return;
}



/* these extended variable options are table driven, to make it easier to add more
   later without messing them up */
/* note: the format is of the form   --output_dir=string   */
/* note2: if the string was quoted as --output_dir="this directory"
   then those quotes were removed by the shell */
static void
ParseExtendedVar(
    char *argsource,
    char *arg_in)
{
    int i;
    struct ext_var_op *pvop_found = NULL;
    struct ext_var_op *pvop_prefix = NULL;
    Bool prefix_ambig = FALSE;
    char *pequals;
    char *argname;		/* the variable name itself */
    char *argval;		/* the part just beyond the equal sign */
    int arglen;
    char *arg;

    /* we're going to modify the argument to split it in half, we we'd
       better make a copy first */
    /* note that the only way out of this routine is through BadArg(),
       which just exits, or the single return() below, so this isn't
       a memory leak*/
    arg = strdup(arg_in);

    /* there must be at least SOME text there */
    if ((strcmp(arg,"--") == 0))
	BadArg(argsource, "Void extended variable argument\n");

    /* find the '=' sign, it MUST be there */
    /* (can't really happen, because the '=' forced us to this routine */
    pequals=strchr(arg,'=');
    if (!pequals)
	BadArg(argsource, "Extended variable argument with no assignment \n");


    /* break the arg in half at the '=' sign (located above) */
    argname = arg+2;
    argval = pequals+1;
    *pequals = '\00';		/* split the string here */
    /* --output_dir=test */
    /*   ^ argname = 1002 */
    /*              ^ argval = 1013 */
    /*  therefore length = argval(1013)-argname(1002)-1 (10) */
    arglen = argval - argname - 1;

    /* search for a match in the extended variable table */
    for (i=0; i < NUM_EXTENDED_VARS; ++i) {
	struct ext_var_op *pvop = &extended_vars[i];

	/* check for an exact match */
	if (strcmp(argname,pvop->var_optname) == 0) {
	    pvop_found = pvop;
	    break;
	}

	/* check for a prefix match */
	if (strncmp(argname,pvop->var_optname,arglen) == 0) {
	    if (pvop_prefix == NULL)
		pvop_prefix = pvop;
	    else
		prefix_ambig = TRUE; /* already found one */
	}
    }


    /* if we never found a match, it's an error */
    if ((pvop_found == NULL) && (pvop_prefix == NULL))
	BadArg(argsource, "Unknown extended variable argument '%s' (see -hargs)\n", arg);


    /* if the prefix is UNambiguous, that's good enough */
    if ((pvop_prefix != NULL) && (!prefix_ambig)) 
	pvop_found = pvop_prefix;

    /* either exact match or good prefix, do it */
    if (pvop_found != NULL) {
	*pvop_found->var_popt = strdup(argval);
	if (debug>2)
	    fprintf(stderr,"Set extended variable '%s' to '%s'\n",
		    argname, *pvop_found->var_popt);
	if (pvop_found->var_verify) {
	    /* call the verification routine */
	    if (debug>2)
		fprintf(stderr,"verifying extended variable '%s'\n", argname);
	    (*pvop_found->var_verify)(argname,*pvop_found->var_popt);
	}
	free(arg);
	return;
    }

    /* ... else ambiguous prefix */
    fprintf(stderr,"Extended variable arg '%s' is ambiguous, it matches:\n", arg);
    for (i=0; i < NUM_EXTENDED_VARS; ++i) {
	struct ext_var_op *pvop = &extended_vars[i];
	if (strncmp(argname,pvop->var_optname,arglen) == 0)
	    fprintf(stderr,"  %s - %s\n",
		    pvop->var_optname, pvop->var_descr);
    }
    BadArg(argsource, "Ambiguous extended variable argument '%s'\n", arg);
    /* never returns */
}



static u_long
VerifyPositive(
    char *varname,
    char *value)
{
    int i, ivalue = 0;

    for (i = 0; i < strlen(value); i++) {
        if (!isdigit((int)value[i])) {
	    fprintf(stderr, 
		    "Value '%s' is not valid for variable '%s'\n", 
		    value, varname);
	    exit(1);
	}
    }
    ivalue = atoi(value);
    if (ivalue <= 0) {
	fprintf(stderr,
		"Value '%s' is not valid for variable '%s'\n", 
		value, varname);
	exit(1);
    }

    return (u_long)ivalue;
}


static void
VerifyUpdateInt(
    char *varname,
    char *value)
{
    update_interval = VerifyPositive(varname, value);
}


static void 
VerifyMaxConnNum(
    char *varname, 
    char *value)
{
    max_conn_num = VerifyPositive(varname, value);
    conn_num_threshold = TRUE;
}


static void 
VerifyLiveConnInt(
    char *varname, 
    char *value)
{
    remove_live_conn_interval = VerifyPositive(varname, value);
}


static void 
VerifyClosedConnInt(
    char *varname, 
    char *value)
{
    remove_closed_conn_interval = VerifyPositive(varname, value);  
}



static void
ParseArgs(
    char *argsource,
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

	if (strncmp(argv[i],"--",2) == 0) {
	    if (strchr(argv[i],'=') != NULL)
		ParseExtendedVar(argsource, argv[i]);
	    else
		ParseExtendedBool(argsource, argv[i]);
	    continue;
	}

	if (*argv[i] == '-') {
	    if (argv[i][1] == '\00') /* just a '-' */
		Usage();

	    while (*(++argv[i]))
		switch (*argv[i]) {
		  case 'A':
		    if (isdigit((int)(*(argv[i]+1))))
			thru_interval = atoi(argv[i]+1);
		    else
			BadArg(argsource, "-A  number missing\n");
		    if (thru_interval <= 0)
			BadArg(argsource, "-A  must be > 1\n");
		    *(argv[i]+1) = '\00'; break;
		  case 'B':
		    if (isdigit((int)(*(argv[i]+1))))
			beginpnum = atoi(argv[i]+1);
		    else
			BadArg(argsource, "-B  number missing\n");
		    if (beginpnum < 0)
			BadArg(argsource, "-B  must be >= 0\n");
		    *(argv[i]+1) = '\00'; break;
		  case 'C': colorplot = TRUE; break;
		  case 'D': hex = FALSE; break;
		  case 'E':
		    if (isdigit((int)(*(argv[i]+1))))
			endpnum = atoi(argv[i]+1);
		    else
			BadArg(argsource, "-E  number missing\n");
		    if (beginpnum < 0)
			BadArg(argsource, "-E  must be >= 0\n");
		    *(argv[i]+1) = '\00'; break;
		  case 'F': graph_segsize = TRUE; break;
		  case 'G':
		    graph_tput = TRUE;
		    graph_tsg = TRUE;
		    graph_rtt = TRUE;
		    graph_owin = TRUE;
		    graph_segsize = TRUE;
		    break;
		  case 'M': colorplot = FALSE; break;
		  case 'N': graph_owin = TRUE; break;
		  case 'O':
		    if (*(argv[i]+1)) {
			/* -Ofile */
			output_filename = strdup(argv[i]+1);
			*(argv[i]+1) = '\00';
		    } else {
			/* maybe -O file */
			BadArg(argsource, "-Ofile requires a file name\n");
		    }
		    break;
		  case 'P': printem = TRUE; break;
		  case 'R': graph_rtt = TRUE; break;
		  case 'S': graph_tsg = TRUE; break;
		  case 'T': graph_tput = TRUE; break;
		  case 'W': print_owin = TRUE; break;
		  case 'X': hex = TRUE; break;
		  case 'Z': dump_rtt = TRUE; break;
		  case 'b': printbrief = TRUE; break;
		  case 'c': ignore_non_comp = TRUE; break;
		  case 'd': ++debug; break;
		  case 'e': save_tcp_data = TRUE; break;
		  case 'f':
		    filter_output = TRUE;
		    if (*(argv[i]+1)) {
			/* -fEXPR */
			ParseFilter(argv[i]+1);
			*(argv[i]+1) = '\00';
		    } else {
			/* -f EXPR */
			BadArg(argsource, "-f requires a filter\n");
		    }
		    break;
		  case 'h': Help(argv[i]+1); *(argv[i]+1) = '\00'; break;
		  case 'i': {
		      int conn = -1;
		      if (run_continuously) {
			fprintf(stderr, "Warning: cannot ignore connections in continuous mode\n");
		      }
		      else {
			  if (isdigit((int)(*(argv[i]+1))))
			      conn = atoi(argv[i]+1);
			  else
			      BadArg(argsource, "-i  number missing\n");
		          if (conn < 0)
			      BadArg(argsource, "-i  must be >= 0\n");
 		          ++saw_i_or_o;
		          IgnoreConn(conn);
		      }
		      *(argv[i]+1) = '\00'; 
		  } break;
		  case 'l': printbrief = FALSE; break;
		  case 'm':
		    BadArg(argsource,
			   "-m option is obsolete (no longer necessary)\n");
		    *(argv[i]+1) = '\00'; break;
		  case 'n':
		    resolve_ipaddresses = FALSE;
		    resolve_ports = FALSE;
		    break;
		  case 'o':
		    if (run_continuously) {
		        fprintf(stderr, "Warning: cannot use 'grab only' flag in continuous mode\n");
		    }
		    else {
		        ++saw_i_or_o;
		        GrabOnly(argsource,argv[i]+1);
		    }
		    *(argv[i]+1) = '\00'; break;
		  case 'p': printallofem = TRUE; break;
		  case 'q': printsuppress = TRUE; break;
		  case 'r': print_rtt = TRUE; break;
		  case 's': use_short_names = TRUE; break;
		  case 't': printticks = TRUE; break;
		  case 'u': do_udp = TRUE; break;
		  case 'v': Version(); exit(0); break;
		  case 'w':
		    warn_printtrunc = TRUE;
		    warn_printbadmbz = TRUE;
		    warn_printhwdups = TRUE;
		    warn_printbadcsum = TRUE;
		    warn_printbad_syn_fin_seq = TRUE;
		    warn_ooo = TRUE;
		    break;
		  case 'x':
		    BadArg(argsource,
			   "unknown module option (-x...)\n");
		    break;
		  case 'y': plot_tput_instant = FALSE; break;
		  case 'z':
		    if (strcmp(argv[i],"z") == 0) {
			/* backward compat, just zero the time */
			graph_time_zero = TRUE;
		    } else if (strcasecmp(argv[i],"zx") == 0) {
			graph_time_zero = TRUE;
		    } else if (strcasecmp(argv[i],"zy") == 0) {
			graph_seq_zero = TRUE;
		    } else if ((strcasecmp(argv[i],"zxy") == 0) ||
			       (strcasecmp(argv[i],"zyx") == 0)) {
			/* set BOTH to zero */
			graph_time_zero = TRUE;
			graph_seq_zero = TRUE;
		    } else {
			BadArg(argsource, "only -z -zx -zy and -zxy are legal\n");
		    }
		    *(argv[i]+1) = '\00';
		    break;
		  default:
		    BadArg(argsource,
			   "option '%c' not understood\n", *argv[i]);
		}
	} else if (*argv[i] == '+') {
	    /* a few of them have a REVERSE flag too */
	    if (argv[i][1] == '\00') /* just a '+' */
		Usage();

	    while (*(++argv[i]))
		switch (*argv[i]) {
		  case 'C': colorplot = !TRUE; break;
		  case 'D': hex = !FALSE; break;
		  case 'F': graph_segsize = !TRUE; break;
		  case 'M': colorplot = !FALSE; break;
		  case 'N': graph_owin = !TRUE; break;
		  case 'P': printem = !TRUE; break;
		  case 'R': graph_rtt = !TRUE; break;
		  case 'S': graph_tsg = !TRUE; break;
		  case 'T': graph_tput = !TRUE; break;
		  case 'W': print_owin = !TRUE; break;
		  case 'X': hex = !TRUE; break;
		  case 'Z': dump_rtt = !TRUE; break;
		  case 'b': printbrief = !TRUE; break;
		  case 'c': ignore_non_comp = !TRUE; break;
		  case 'e': save_tcp_data = FALSE; break;
		  case 'l': printbrief = !FALSE; break;
		  case 'n':
		    resolve_ipaddresses = !FALSE;
		    resolve_ports = !FALSE;
		    break;
		  case 'p': printallofem = !TRUE; break;
		  case 'q': printsuppress = !TRUE; break;
		  case 'r': print_rtt = !TRUE; break;
		  case 's': use_short_names = !TRUE; break;
		  case 't': printticks = !TRUE; break;
		  case 'u': do_udp = !TRUE; break;
		  case 'w':
		    warn_printtrunc = !TRUE;
		    warn_printbadmbz = !TRUE;
		    warn_printhwdups = !TRUE;
		    warn_printbadcsum = !TRUE;
		    warn_ooo = !TRUE;
		    break;
		  case 'y': plot_tput_instant = !plot_tput_instant; break;
		  case 'z':
		    if (strcmp(argv[i],"z") == 0) {
			/* backward compat, just zero the time */
			graph_time_zero = !TRUE;
		    } else if (strcasecmp(argv[i],"zx") == 0) {
			graph_time_zero = !TRUE;
		    } else if (strcasecmp(argv[i],"zy") == 0) {
			graph_seq_zero = !TRUE;
		    } else if ((strcasecmp(argv[i],"zxy") == 0) ||
			       (strcasecmp(argv[i],"zyx") == 0)) {
			/* set BOTH to zero */
			graph_time_zero = !TRUE;
			graph_seq_zero = !TRUE;
		    } else {
			BadArg(argsource, "only +z +zx +zy and +zxy are legal\n");
		    }
		    *(argv[i]+1) = '\00';
		    break;
		  default:
		    Usage();
		}
	} else {
	    filenames = &argv[i];
	    *pargc -= i;
	    return;
	}
    }

    return;
}


static void
DumpFlags(void)
{
    int i;

    fprintf(stderr,"printbrief:       %s\n", BOOL2STR(printbrief));
    fprintf(stderr,"printsuppress:    %s\n", BOOL2STR(printsuppress));
    fprintf(stderr,"print_rtt:        %s\n", BOOL2STR(print_rtt));
    fprintf(stderr,"graph tsg:        %s\n", BOOL2STR(graph_tsg));
    fprintf(stderr,"graph rtt:        %s\n", BOOL2STR(graph_rtt));
    fprintf(stderr,"graph tput:       %s\n", BOOL2STR(graph_tput));
    fprintf(stderr,"plotem:           %s\n",
	    colorplot?"(color)":"(b/w)");
    fprintf(stderr,"hex printing:     %s\n", BOOL2STR(hex));
    fprintf(stderr,"ignore_non_comp:  %s\n", BOOL2STR(ignore_non_comp));
    fprintf(stderr,"printem:          %s\n", BOOL2STR(printem));
    fprintf(stderr,"printallofem:     %s\n", BOOL2STR(printallofem));
    fprintf(stderr,"printticks:       %s\n", BOOL2STR(printticks));
    fprintf(stderr,"use_short_names:  %s\n", BOOL2STR(use_short_names));
    fprintf(stderr,"save_tcp_data:    %s\n", BOOL2STR(save_tcp_data));
    fprintf(stderr,"graph_time_zero:  %s\n", BOOL2STR(graph_time_zero));
    fprintf(stderr,"graph_seq_zero:   %s\n", BOOL2STR(graph_seq_zero));
    fprintf(stderr,"beginning pnum:   %lu\n", beginpnum);
    fprintf(stderr,"ending pnum:      %lu\n", endpnum);
    fprintf(stderr,"throughput intvl: %d\n", thru_interval);
    fprintf(stderr,"number modules:   %u\n", (unsigned)NUM_MODULES);
    fprintf(stderr,"debug:            %s\n", BOOL2STR(debug));

    /* print out the stuff controlled by the extended boolean args */
    for (i=0; i < NUM_EXTENDED_BOOLS; ++i) {
	struct ext_bool_op *pbop = &extended_bools[i];
	char buf[100];
	snprintf(buf,sizeof(buf),"%s:", pbop->bool_optname);
	fprintf(stderr,"%-18s%s\n", buf, BOOL2STR(*pbop->bool_popt));
    }

    /* print out the stuff controlled by the extended variable args */
    for (i=0; i < NUM_EXTENDED_VARS; ++i) {
	struct ext_var_op *bvop = &extended_vars[i];
	char buf[100];
	snprintf(buf,sizeof(buf),"%s:", bvop->var_optname);
	fprintf(stderr,"%-18s%s\n", buf,
		(*bvop->var_popt)?*bvop->var_popt:"<NULL>");
    }
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
	    fprintf(stderr,"Calling newconn routine for module \"%s\"\n",
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


void
ModulesPerOldConn(
		  tcp_pair *ptp)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_deleteconn == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling delete conn routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_deleteconn)(ptp,
					ptp->pmod_info?ptp->pmod_info[i]:NULL);
    }
}


static void
ModulesPerUDPConn(
    udp_pair *pup)
{
    int i;
    void *pmodstruct;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_udp_newconn == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling UDP newconn routine for module \"%s\"\n",
		    modules[i].module_name);

	pmodstruct = (*modules[i].module_udp_newconn)(pup);
	if (pmodstruct) {
	    /* make sure the array is there */
	    if (!pup->pmod_info) {
		pup->pmod_info = MallocZ(num_modules * sizeof(void *));
	    }

	    /* remember this structure */
	    pup->pmod_info[i] = pmodstruct;
	}
    }
}

static void
ModulesPerNonTCPUDP(
    struct ip *pip,
    void *plast)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_nontcpudp_read == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling nontcp routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_nontcpudp_read)(pip,plast);
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

	if (modules[i].module_read == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling read routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_read)(pip,ptp,plast,
				  ptp->pmod_info?ptp->pmod_info[i]:NULL);
    }
}


static void
ModulesPerUDPPacket(
    struct ip *pip,
    udp_pair *pup,
    void *plast)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_udp_read == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling read routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_udp_read)(pip,pup,plast,
				      pup->pmod_info?pup->pmod_info[i]:NULL);
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


/* read from a file, store contents into NULL-terminated string */
/* memory returned must be "free"ed to be reclaimed */
static char *
FileToBuf(
    char *filename)
{
    FILE *f;
    struct stat str_stat;
    int filesize;
    char *buffer;

    /* open the file */
    if ((f = fopen(filename,"r")) == NULL) {
	fprintf(stderr,"Open of '%s' failed\n", filename);
	perror(filename);
	return(NULL);
    }


    /* determine the file length */
    if (fstat(fileno(f),&str_stat) != 0) {
	perror("fstat");
	exit(1);
    }
    filesize = str_stat.st_size;

    /* make a big-enough buffer */
    buffer = MallocZ(filesize+2);  /* with room to NULL terminate */


    /* read the file into the buffer */
    if (fread(buffer,1,filesize,f) != filesize) {
	perror("fread");
	exit(1);
    }

    fclose(f);

    /* put a NULL at the end */
    buffer[filesize] = '\00';

    if (debug > 1)
	printf("Read %d characters from resource '%s': '%s'\n",
	       filesize, filename, buffer);

    /* somebody else will "free" it */
    return(buffer);
}


/* ExpandFormat:
   Expand the string in "format" and return the result string

   The return value rotates between one of two static strings
   (to avoid malloc overhead), but if you need more than two at
   a time, you'll need to make a copy.

   Expansions are performed as follows:

   %f	basename of the current input file
   %d	execution date, standard unix output, spaces ==> underscores
   %t	execution time & date, standard unix output, spaces ==> underscores
   %D	execution date, format "1-14-1963"
*/

char *
ExpandFormat(const char *format)
{
    static struct dstring *pds1 = NULL;
    static struct dstring *pds2 = NULL;
    static struct dstring *pds = NULL;

    /* init the strings */
    if (pds1 == NULL) {
	pds1 = DSNew();
	pds2 = DSNew();
    }

    /* alternate between them */
    pds = (pds == pds1)?pds2:pds1;

    /* erase the previous contents */
    DSErase(pds);

    if (debug>2)
	fprintf(stderr,"Trying to expand string '%s'\n", format);

    while (*format) {
	if (strncmp(format,"%f",2) == 0) {
	    /* basename of current file (after the last slash) */
	    char *filename = cur_filename;
	    char *ptr;

	    /* find the last '/' in the file */
	    ptr = strrchr(filename,'/');

	    if (ptr)
		++ptr;		/* the base of the filename is one past the slash */
	    else
		ptr = filename;	/* no directory, just use the file */
		
	    DSAppendString(pds,ptr);
	    format += 2;
	} else if (strncmp(format,"%D",2) == 0) {
	    /* current wallclock date (1-14-1963) */
	    time_t now;
	    struct tm *ptm;
	    char buf[32];

	    /* get the current time, broken apart */
	    time(&now);
	    ptm = localtime((time_t *)&wallclock_start.tv_sec);

	    snprintf(buf,sizeof(buf),"%d-%d-%d",
		    ptm->tm_mon+1,
		    ptm->tm_mday,
		    1900 + ptm->tm_year);
	    DSAppendString(pds,buf);
	    format += 2;
	} else if ((strncmp(format,"%d",2) == 0) ||
		   (strncmp(format,"%t",2) == 0)) {
	    /* current wallclock date, unix format */
	    time_t now;
	    char *pbuf;
	    char *pch;

	    /* get the current time in unix format */
            /* Fri Sep 13 00:00:00 1986\n\0 */
	    /*           1         2       */
	    /* 0123456789012345678901234 5 */
	    time(&now);
	    pbuf = ctime(&now);
	    pbuf[24] = '\00';	/* nuke the newline */

	    /* spaces to underscores */
	    for (pch = pbuf; *pch; ++pch)
		if (*pch == ' ')
		    *pch = '_';


	    if (strncmp(format,"%d",2) == 0)
		/* the whole thing */
		DSAppendString(pds,pbuf);
	    else {
		/* just the date */
		pbuf[11] = '\00';
		DSAppendString(pds,pbuf);
		DSAppendString(pds,pbuf+20);
	    }

	    format += 2;
	} else {
	    /* no formatting, just copy one character */
	    DSAppendChar(pds,*format);
	    ++format;
	}
    }

    return(DSVal(pds));
}

