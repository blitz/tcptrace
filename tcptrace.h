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
static char const rcsid_tcptrace[] =
    "@(#)$Header$";


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#if __FreeBSD__ >= 2
#include <osreldate.h>
#if __FreeBSD_version >= 300000
#include <net/if_var.h>
#endif
#endif          
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdlib.h>
#include <math.h>

/* IPv6 support */
#include "ipv6.h"

/* we want LONG LONG in some places */
#if SIZEOF_UNSIGNED_LONG_LONG_INT >= 8
#define HAVE_LONG_LONG
typedef unsigned long long int u_llong;
typedef long long int llong;
/* Thanks to MacOSX, they use %qu to print unsigned long long ints */
/* There is a test to see if we need to use %qu or %llu to print these variables */
/* The test is located in configure.in */
#ifdef USE_LLU
#define FS_ULL "llu" /* For most systems use llu */
#define FS_LL  "lld" /* For most systems use ll */
#else /* USE_LLU */
#define FS_ULL "qu"  /* MacOSX use qu */
#define FS_LL  "qd"  /* MacOSX use qd */
#endif /* USE_LLU */

#else /* LONG LONG */
typedef unsigned long int u_llong;
typedef long int llong;
#define FS_ULL "lu" /* No long long unsigned, so  use lu */
#define FS_LL  "ld" /* No long long ints, so use ld */
#endif /* LONG LONG */

/* plotter information */
typedef int PLOTTER;
#define NO_PLOTTER -1
#define NCOLORS 8
extern char *ColorNames[NCOLORS];
/* {"green", "red", "blue", "yellow", "purple", "orange", "magenta", "pink"}; */
typedef struct pl_line *PLINE;


/* type for a TCP sequence number, ACK, FIN, or SYN */
typedef u_long seqnum;

/* length of a segment */
typedef u_long seglen;

/* type for a quadrant number */
typedef u_char quadnum;  /* 1,2,3,4 */

/* type for a TCP port number */
typedef u_short portnum;

/* type for an IP address */
/* IP address can be either IPv4 or IPv6 */
typedef struct ipaddr {
    u_char addr_vers;	/* 4 or 6 */
    union {
	struct in_addr   ip4;
	struct in6_addr  ip6;
    } un;
} ipaddr;


/* some machines (TRUE64 for one) handle the 4-bit TCP/IP fields
   differently, so this macro simplifies life */
#define IP_HL(pip)   (pip->ip_hl)
#define IP_OFF(pip)  (pip->ip_off)
#define TH_OFF(ptcp) (ptcp->th_off)
#define TH_X2(ptcp)  (ptcp->th_x2)



/* type for a timestamp */
typedef struct timeval timeval;
#define ZERO_TIME(ptv)(((ptv)->tv_sec == 0) && ((ptv)->tv_usec == 0))


/* type for a Boolean */
typedef u_char Bool;
#define TRUE	1
#define FALSE	0
#define BOOL2STR(b) (b)?"TRUE":"FALSE"

/* ACK types */
enum t_ack {NORMAL = 1,		/* no retransmits, just advance */
	    AMBIG = 2,		/* segment ACKed was rexmitted */
	    CUMUL = 3,		/* doesn't advance */
	    TRIPLE = 4,		/* triple dupack */
	    NOSAMP = 5};	/* covers retransmitted segs, no rtt sample */

/* type for an internal file pointer */
typedef struct mfile MFILE;

/* file name information */
extern char **filenames;	/* all the files on the cmd line */
extern char *cur_filename;	/* the current file */

/* first and last packet timestamp */
extern timeval first_packet;
extern timeval last_packet;

/* counters */
extern u_long tcp_trace_count;
extern u_long udp_trace_count;


#ifdef OLD
/* test 2 IP addresses for equality */
#define IP_SAMEADDR(addr1,addr2) (((addr1).s_addr) == ((addr2).s_addr))

/* copy IP addresses */
#define IP_COPYADDR(toaddr,fromaddr) ((toaddr).s_addr = (fromaddr).s_addr)
#endif

typedef struct segment {
    seqnum	seq_firstbyte;	/* seqnumber of first byte */
    seqnum 	seq_lastbyte;	/* seqnumber of last byte */
    u_char	retrans;	/* retransmit count */
    u_int	acked;		/* how MANY times has has it been acked? */
    timeval	time;		/* time the segment was sent */
    struct segment *next;
    struct segment *prev;
} segment;

typedef struct quadrant {
    segment	*seglist_head;
    segment	*seglist_tail;
    Bool 	full;
    struct quadrant *prev;
    struct quadrant *next;
} quadrant;

typedef struct seqspace {
    quadrant 	*pquad[4];
} seqspace;

typedef struct tcb {
    /* parent pointer */
    struct stcp_pair *ptp;
    struct tcb	*ptwin;

    /* TCP information */
    seqnum	ack;
    seqnum	seq;
    seqnum	syn;
    seqnum	fin;
    seqnum	windowend;
    timeval	time;

    /* TCP options */
    u_int	mss;
    Bool	f1323_ws;	/* did he request 1323 window scaling? */
    Bool	f1323_ts;	/* did he request 1323 timestamps? */
    Bool	fsack_req;	/* did he request SACKs? */
    u_char	window_scale;

    /* statistics added */
    u_llong	data_bytes;
    u_llong	data_pkts;
    u_llong	data_pkts_push;
    u_llong	unique_bytes;	/* bytes sent (-FIN/SYN), excluding rexmits */
    u_llong	rexmit_bytes;
    u_llong	rexmit_pkts;
    u_llong	ack_pkts;
    u_llong	pureack_pkts;	/* mallman - pure acks, no data */
    u_long	win_max;
    u_long	win_min;
    u_long	win_tot;
    u_long	win_zero_ct;
    u_llong	packets;
    u_char	syn_count;
    u_char	fin_count;
    u_char	reset_count;  /* resets SENT */
    u_long	min_seg_size;
    u_long	max_seg_size;
    u_llong	out_order_pkts;	/* out of order packets */
    u_llong	sacks_sent;	/* sacks returned */
    u_long	ipv6_segments;	/* how many segments were ipv6? */

    /* stats on sequence numbers */
    seqnum	min_seq;	/* smallest seq number seen */
    seqnum	max_seq;	/* largest seq number seen */
    seqnum	latest_seq;	/* most recent seq number seen */

    /* hardware duplicate detection */
#define SEGS_TO_REMEMBER 8
    struct str_hardware_dups {
	seqnum	hwdup_seq;	/* sequence number */
	u_short	hwdup_id;	/* IP ID */
	u_long	hwdup_packnum; /* packet number */
    } hardware_dups[SEGS_TO_REMEMBER];
    u_long num_hardware_dups;
    u_char hardware_dups_ix;

    /* did I detect any "bad" tcp behavior? */
    /* at present, this means: */
    /*  - SYNs retransmitted with different sequence numbers */
    /*  - FINs retransmitted with different sequence numbers */
    Bool	bad_behavior;

    /* added for initial window stats (for Mallman) */
    u_long	initialwin_bytes;	/* initial window (in bytes) */
    u_long	initialwin_segs;	/* initial window (in segments) */
    Bool	data_acked;	/* has any non-SYN data been acked? */

    /* added for (estimated) congestions window stats (for Mallman) */
    u_long	owin_max;
    u_long	owin_min;
    u_llong	owin_tot;

    /* RTT stats for singly-transmitted segments */
    double	rtt_last;	/* RTT as of last good ACK (microseconds) */
    u_long	rtt_min;
    u_long	rtt_max;
    double	rtt_sum;	/* for averages */
    double	rtt_sum2;	/* sum of squares, for stdev */
    u_long	rtt_count;	/* for averages */
    /* RTT stats for multiply-transmitted segments */
    u_long	rtt_min_last;
    u_long	rtt_max_last;
    double	rtt_sum_last;	/* from last transmission, for averages */
    double	rtt_sum2_last;	/* sum of squares, for stdev */
    u_long	rtt_count_last;	/* from last transmission, for averages */
    /* ACK Counters */
    u_llong	rtt_amback;	/* ambiguous ACK */
    u_llong	rtt_cumack;	/* segments only cumulativly ACKed */
    u_llong	rtt_nosample;	/* segments ACKED, but after retransmission */
				/* of earlier segments, so sample isn't */
				/* valid */
    u_llong	rtt_unkack;	/* unknown ACKs  ??? */
    u_llong	rtt_dupack;	/* duplicate ACKs */
    u_llong	rtt_triple_dupack; /* triple duplicate ACKs */
    /* retransmission information */
    seqspace    *ss;		/* the sequence space*/
    u_long	retr_max;	/* maximum retransmissions ct */
    u_long	retr_min_tm;	/* minimum retransmissions time */
    u_long	retr_max_tm;	/* maximum retransmissions time */
    double	retr_tm_sum;	/* for averages */
    double	retr_tm_sum2;	/* sum of squares, for stdev */
    u_long	retr_tm_count;	/* for averages */

    /* Instantaneous throughput info */
    timeval	thru_firsttime;	/* time of first packet this interval */
    u_long	thru_bytes;	/* number of bytes this interval */
    u_long	thru_pkts;	/* number of packets this interval */
    PLOTTER	thru_plotter;	/* throughput data dump file */
    timeval	thru_lasttime;	/* time of previous segment */
    PLINE	thru_avg_line;	/* average throughput line */
    PLINE	thru_inst_line;	/* instantaneous throughput line */

    /* data transfer time stamps - mallman */
    timeval	first_data_time;
    timeval	last_data_time;

    /* Time Sequence Graph info for this one */
    PLOTTER	tsg_plotter;
    char	*tsg_plotfile;

    /* Dumped RTT samples */
    MFILE	*rtt_dump_file;

    /* Extracted stream contents */
    MFILE	*extr_contents_file;
    u_llong	trunc_bytes;	/* data bytes not see due to trace file truncation */
    u_llong	trunc_segs;	/* segments with trunc'd bytes */
    seqnum	extr_lastseq;	/* last sequence number we stored */
    seqnum	extr_initseq;	/* initial sequence number (same as SYN unless we missed it) */

    /* RTT Graph info for this one */
    PLOTTER	rtt_plotter;
    PLINE	rtt_line;

    /* Segment size graph */
    PLOTTER	segsize_plotter;
    PLINE	segsize_line;
    PLINE	segsize_avg_line;

    /* Congestion window graph */
    PLOTTER	owin_plotter;
    PLINE	owin_line;
    PLINE	owin_avg_line;

    /* for tracking unidirectional idle time */
    timeval	last_time;	/* last packet SENT from this side */
    u_llong	idle_max;	/* maximum idle time observed (usecs) */

    /* for looking for interesting SACK blocks */
    u_long	num_sacks;
    u_long	max_sack_blocks;

    /* host name letter(s) */
    char	*host_letter;
} tcb;


typedef u_short hash;

typedef struct {
    ipaddr	a_address;
    ipaddr	b_address;
    portnum	a_port;
    portnum	b_port;
    hash	hash;
} tcp_pair_addrblock;


struct stcp_pair {
    /* are we ignoring this one?? */
    Bool		ignore_pair;

    /* inactive (previous instance of current connection */
    Bool		inactive;

    /* endpoint identification */
    tcp_pair_addrblock	addr_pair;

    /* connection naming information */
    char		*a_hostname;
    char		*b_hostname;
    char		*a_portname;
    char		*b_portname;
    char		*a_endpoint;
    char		*b_endpoint;

    /* connection information */
    timeval		first_time;
    timeval		last_time;
    u_llong		packets;
    tcb			a2b;
    tcb			b2a;

    /* module-specific structures, if requested */
    void		**pmod_info;

    /* which file this connection is from */
    char		*filename;
};
typedef struct stcp_pair tcp_pair;

typedef struct tcphdr tcphdr;


extern int num_tcp_pairs;	/* how many pairs are in use */
extern tcp_pair **ttp;		/* array of pointers to allocated pairs */


/* minimal support for UDP "connections" */
typedef struct ucb {
    /* parent pointer */
    struct sudp_pair *pup;
    struct ucb	*ptwin;

    /* statistics added */
    u_llong	data_bytes;
    u_llong	packets;
    u_long	min_dg_size;
    u_long	max_dg_size;

    /* host name letter(s) */
    char	*host_letter;
} ucb;



typedef tcp_pair_addrblock udp_pair_addrblock;
struct sudp_pair {
    /* endpoint identification */
    udp_pair_addrblock	addr_pair;

    /* connection naming information */
    char		*a_hostname;
    char		*b_hostname;
    char		*a_portname;
    char		*b_portname;
    char		*a_endpoint;
    char		*b_endpoint;

    /* connection information */
    timeval		first_time;
    timeval		last_time;
    u_llong		packets;
    ucb			a2b;
    ucb			b2a;

    /* module-specific structures, if requested */
    void		**pmod_info;

    /* which file this connection is from */
    char		*filename;

    /* linked list of usage */
    struct sudp_pair *next;
};
typedef struct sudp_pair udp_pair;
typedef struct udphdr udphdr;


extern int num_udp_pairs;	/* how many pairs are in use */
extern udp_pair **utp;		/* array of pointers to allocated pairs */


/* option flags */
extern Bool colorplot;
extern Bool dump_rtt;
extern Bool graph_rtt;
extern Bool graph_tput;
extern Bool graph_tsg;
extern Bool graph_segsize;
extern Bool graph_owin;
extern Bool hex;
extern Bool ignore_non_comp;
extern Bool resolve_ipaddresses;
extern Bool resolve_ports;
extern Bool triple_dupack_allows_data;
extern Bool verify_checksums;
extern Bool print_rtt;
extern Bool print_owin;
extern Bool printbrief;
extern Bool printsuppress;
extern Bool printem;
extern Bool printallofem;
extern Bool printticks;
extern Bool dump_packet_data;
extern Bool warn_ooo;
extern Bool warn_printtrunc;
extern Bool warn_printbadmbz;
extern Bool warn_printhwdups;
extern Bool warn_printbad_syn_fin_seq;
extern Bool show_out_order;
extern Bool show_rexmit;
extern Bool show_zero_window;
extern Bool show_sacks;
extern Bool show_rtt_dongles;
extern Bool show_triple_dupack;
extern Bool use_short_names;
extern Bool save_tcp_data;
extern Bool graph_time_zero;
extern Bool graph_seq_zero;
extern Bool graph_zero_len_pkts;
extern Bool plot_tput_instant;
extern Bool filter_output;
extern Bool do_udp;
extern Bool show_title;
extern int debug;
extern int thru_interval;
extern u_long pnum;

/* extended variables with values */
extern char *output_file_dir;
extern char *output_file_prefix;

extern u_long ctrunc;
extern timeval current_time;
extern char *output_filename;

/* first and last packet timestamp */
extern timeval first_packet;
extern timeval last_packet;


#define MAX_NAME 20



/* external routine decls */
double sqrt(double x);
void free(void *);
int finite(double);

/* note that many machines have an ether_ntoa, but the output differs, as does
   the prototype, so we'll include our own and change the name to avoid conflicts
   with local prototypes if they exist and differ */
char *Ether_Ntoa(struct ether_addr *e);

/* global routine decls */
void *MallocZ(int);
void *ReallocZ(void *oldptr, int obytes, int nbytes);
void trace_init(void);
void trace_done(void);
void seglist_init(tcb *);
void printpacket(int, int, void *, int, struct ip *, void *plast);
void plotter_vtick(PLOTTER, timeval, u_long);
void plotter_utick(PLOTTER, timeval, u_long);
void plotter_uarrow(PLOTTER, timeval, u_long);
void plotter_tick(PLOTTER, timeval, u_long, char);
void plotter_text(PLOTTER, timeval, u_long, char *, char  *);
void plotter_temp_color(PLOTTER, char *color);
void plotter_ltick(PLOTTER, timeval, u_long);
void plotter_rtick(PLOTTER, timeval, u_long);
void plotter_rarrow(PLOTTER, timeval, u_long);
void plotter_plus(PLOTTER, timeval, u_long);
void plotter_perm_color(PLOTTER, char *color);
void plotter_line(PLOTTER, timeval, u_long, timeval, u_long);
void plotter_larrow(PLOTTER, timeval, u_long);
void plotter_htick(PLOTTER, timeval, u_long);
void plotter_dtick(PLOTTER, timeval, u_long);
void plotter_dot(PLOTTER, timeval, u_long);
void plotter_done(void);
void plotter_dline(PLOTTER, timeval, u_long, timeval, u_long);
void plotter_diamond(PLOTTER, timeval, u_long);
void plotter_darrow(PLOTTER, timeval, u_long);
void plotter_box(PLOTTER, timeval, u_long);
void plotter_arrow(PLOTTER, timeval, u_long, char);
void plotter_nothing(PLOTTER pl, struct timeval t);
void plot_init(void);
tcp_pair *dotrace(struct ip *, struct tcphdr *ptcp, void *plast);
void PrintRawData(char *label, void *pfirst, void *plast, Bool octal);
void PrintRawDataHex(char *label, void *pfirst, void *plast);
void PrintTrace(tcp_pair *);
void UDPPrintTrace(udp_pair *);
void PrintBrief(tcp_pair *);
void UDPPrintBrief(udp_pair *);
void OnlyConn(int);
void IgnoreConn(int);
double elapsed(timeval, timeval);
void tv_sub(struct timeval *plhs, struct timeval rhs);
void tv_add(struct timeval *plhs, struct timeval rhs);
int tv_cmp(struct timeval lhs, struct timeval rhs);
Bool tv_same(struct timeval lhs, struct timeval rhs);
char *elapsed2str(double etime);
int ConnReset(tcp_pair *);
int ConnComplete(tcp_pair *);
u_int SynCount(tcp_pair *ptp);
u_int FinCount(tcp_pair *ptp);
char *ts2ascii(timeval *);
char *ts2ascii_date(timeval *);
char *ServiceName(portnum);
char *HostName(ipaddr);
char *HostAddr(ipaddr);
char *HostLetter(u_int);
char *NextHostLetter(void);
char *EndpointName(ipaddr,portnum);
PLOTTER new_plotter(tcb *plast, char *filename, char *title,
		    char *xlabel, char *ylabel, char *suffix);
int rexmit(tcb *, seqnum, seglen, Bool *);
enum t_ack ack_in(tcb *, seqnum, unsigned tcp_data_length);
void DoThru(tcb *ptcb, int nbytes);
struct mfile *Mfopen(char *fname, char *mode);
void Minit(void);
int Mfileno(MFILE *pmf);
int Mvfprintf(MFILE *pmf, char *format, va_list ap);
int Mfwrite(void *buf, u_long size, u_long nitems, MFILE *pmf);
long Mftell(MFILE *pmf);
int Mfseek(MFILE *pmf, long offset, int ptrname);
int Mfprintf(MFILE *pmf, char *format, ...);
int Mfflush(MFILE *pmf);
int Mfclose(MFILE *pmf);
int Mfpipe(int pipes[2]);
struct tcp_options *ParseOptions(struct tcphdr *ptcp, void *plast);
FILE *CompOpenHeader(char *filename);
FILE *CompOpenFile(char *filename);
void CompCloseFile(char *filename);
void CompFormats(void);
int CompIsCompressed(void);
Bool FileIsStdin(char *filename);
struct tcb *ptp2ptcb(tcp_pair *ptp, struct ip *pip, struct tcphdr *ptcp);
void IP_COPYADDR (ipaddr *toaddr, ipaddr fromaddr);
int IP_SAMEADDR (ipaddr addr1, ipaddr addr2);
void PcapSavePacket(char *filename, struct ip *pip, void *plast);
void StringToArgv(char *buf, int *pargc, char ***pargv);
void CopyAddr(tcp_pair_addrblock *, struct ip *pip,portnum,portnum);
int WhichDir(tcp_pair_addrblock *, tcp_pair_addrblock *);
int SameConn(tcp_pair_addrblock *, tcp_pair_addrblock *, int *);
Bool ip_cksum_valid(struct ip *pip, void *plast);
Bool tcp_cksum_valid(struct ip *pip, struct tcphdr *ptcp, void *plast);
Bool udp_cksum_valid(struct ip *pip, struct udphdr *pudp, void *plast);
ipaddr *str2ipaddr(char *str);
int IPcmp(ipaddr *pipA, ipaddr *pipB);

/* high-level line drawing */
PLINE new_line(PLOTTER pl, char *label, char *color);
void extend_line(PLINE pline, timeval xval, int yval);

/* UDP support routines */
void udptrace_init(void);
void udptrace_done(void);
udp_pair *udpdotrace(struct ip *pip, struct udphdr *pudp, void *plast);

/* filter routines */
void HelpFilter(void);
void ParseFilter(char *expr);
Bool PassesFilter(tcp_pair *ptp);

/* TCP flags macros */
#define SYN_SET(ptcp)((ptcp)->th_flags & TH_SYN)
#define FIN_SET(ptcp)((ptcp)->th_flags & TH_FIN)
#define ACK_SET(ptcp)((ptcp)->th_flags & TH_ACK)
#define RESET_SET(ptcp)((ptcp)->th_flags & TH_RST)
#define PUSH_SET(ptcp)((ptcp)->th_flags & TH_PUSH)
#define URGENT_SET(ptcp)((ptcp)->th_flags & TH_URG)
#define FLAG6_SET(ptcp)((ptcp)->th_flags & 0x40)
#define FLAG7_SET(ptcp)((ptcp)->th_flags & 0x80)
#define CWR_SET(ptcp)     (TH_X2((ptcp)) & TH_CWR)
#define ECN_ECHO_SET(ptcp)(TH_X2((ptcp)) & TH_ECN_ECHO)


/* connection directions */
#define A2B 1
#define B2A -1


/*macros for maintaining the seqspace used for rexmit*/
#define QUADSIZE	(0x40000000)
#define QUADNUM(seq)	((seq>>30)+1)
#define IN_Q1(seq)	(QUADNUM(seq)==1)
#define IN_Q2(seq)	(QUADNUM(seq)==2)
#define IN_Q3(seq)	(QUADNUM(seq)==3)
#define IN_Q4(seq)	(QUADNUM(seq)==4)
#define FIRST_SEQ(quadnum)	(QUADSIZE*(quadnum-1))
#define LAST_SEQ(quadnum)	((QUADSIZE*quadnum)-1) /* bug fix by Priya */
#define BOUNDARY(beg,fin) (QUADNUM((beg)) != QUADNUM((fin)))


/* physical layers currently understood					*/
#define PHYS_ETHER	1
#define PHYS_FDDI       2

/*
 * SEQCMP - sequence space comparator
 *	This handles sequence space wrap-around. Overlow/Underflow makes
 * the result below correct ( -, 0, + ) for any a, b in the sequence
 * space. Results:	result	implies
 *			  - 	 a < b
 *			  0 	 a = b
 *			  + 	 a > b
 */
#define	SEQCMP(a, b)		((long)(a) - (long)(b))
#define	SEQ_LESSTHAN(a, b)	(SEQCMP(a,b) < 0)
#define	SEQ_GREATERTHAN(a, b)	(SEQCMP(a,b) > 0)


/* SACK TCP options (not an RFC yet, mostly from draft and RFC 1072) */
/* I'm assuming, for now, that the draft version is correct */
/* sdo -- Tue Aug 20, 1996 */
#define	TCPOPT_SACK_PERM 4	/* sack-permitted option */
#define	TCPOPT_SACK      5	/* sack attached option */
#define	MAX_SACKS       10	/* max number of sacks per segment (rfc1072) */
typedef struct sack_block {
    seqnum	sack_left;	/* left edge */
    seqnum	sack_right;	/* right edge */
} sack_block;

#define MAX_UNKNOWN 16
typedef struct opt_unknown {
    u_char	unkn_opt;
    u_char	unkn_len;
} opt_unknown;

/* RFC 1323 TCP options (not usually in tcp.h yet) */
#define	TCPOPT_WS	3	/* window scaling */
#define	TCPOPT_TS	8	/* timestamp */

/* other options... */
#define	TCPOPT_ECHO		6	/* echo (rfc1072) */
#define	TCPOPT_ECHOREPLY	7	/* echo (rfc1072) */
#define TCPOPT_TIMESTAMP	8	/* timestamps (rfc1323) */
#define TCPOPT_CC		11	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCNEW		12	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCECHO		13	/* T/TCP CC options (rfc1644) */

/* RFC 2481 (ECN) IP and TCP flags (not usually defined yet) */
#define IPTOS_ECT	0x02	/* ECN-Capable Transport */
#define IPTOS_CE	0x01	/* Experienced Congestion */

#define TH_ECN_ECHO	0x02	/* Used by receiver to echo CE bit */
#define TH_CWR		0x01	/* Congestion Window Reduced */



/* some compilers seem to want to make "char" unsigned by default, */
/* which is breaking stuff.  Rather than introduce (more) ugly */
/* machine dependencies, I'm going to FORCE some chars to be */
/* signed... */
typedef signed char s_char;

struct tcp_options {
    short	mss;		/* maximum segment size 	*/
    s_char	ws;		/* window scale (1323) 		*/
    long	tsval;		/* Time Stamp Val (1323)	*/
    long	tsecr;		/* Time Stamp Echo Reply (1323)	*/

    Bool	sack_req;	/* sacks requested 		*/
    s_char	sack_count;	/* sack count in this packet */
    sack_block	sacks[MAX_SACKS]; /* sack blocks */

    /* echo request and reply */
    /* assume that value of -1 means unused  (?) */
    u_long	echo_req;
    u_long	echo_repl;

    /* T/TCP stuff */
    /* assume that value of -1 means unused  (?) */
    u_long	cc;
    u_long	ccnew;
    u_long	ccecho;

    /* record the stuff we don't understand, too */
    char	unknown_count;	/* number of unknown options */
    opt_unknown	unknowns[MAX_UNKNOWN]; /* unknown options */
};



/*
 * File extensions to use
 *
 */
#define RTT_DUMP_FILE_EXTENSION		"_rttraw.dat"
#define RTT_GRAPH_FILE_EXTENSION	"_rtt.xpl"
#define PLOT_FILE_EXTENSION		"_tsg.xpl"
#define SEGSIZE_FILE_EXTENSION		"_ssize.xpl"
#define OWIN_FILE_EXTENSION		"_owin.xpl"
#define THROUGHPUT_FILE_EXTENSION	"_tput.xpl"
#define CONTENTS_FILE_EXTENSION		"_contents.dat"

/* name of file to store filtered output into */
#define PASS_FILTER_FILENAME		"PF"

/* name of the resource file */
#define TCPTRACE_RC_FILE ".tcptracerc"

/* name of the argument envariable */
#define TCPTRACE_ENVARIABLE "TCPTRACEOPTS"

/* packet-reading options... */
/* the type for a packet reading routine */
typedef int pread_f(struct timeval *, int *, int *, void **,
		   int *, struct ip **, void **);

/* give the prototypes for the is_GLORP() routines supported */
#ifdef GROK_SNOOP
	pread_f *is_snoop(void);
#endif /* GROK_SNOOP */
#ifdef GROK_NETM
	pread_f *is_netm(void);
#endif /* GROK_NETM */
#ifdef GROK_TCPDUMP
	pread_f *is_tcpdump(void);
#endif /* GROK_TCPDUMP */
#ifdef GROK_ETHERPEEK
	pread_f *is_EP(void);
#endif /* GROK_ETHERPEEK */
#ifdef GROK_NS
 	pread_f *is_ns(void);
#endif /* GROK_NS */
#ifdef GROK_NLANR
	pread_f *is_nlanr(void);
#endif /* GROK_NLANR */
#ifdef GROK_NETSCOUT
	pread_f *is_netscout(void);
#endif /* GROK_NETSCOUT */


/* I've had problems with the memcpy function that gcc stuffs into the program
   and alignment problems.  This should fix it! */
void *MemCpy(void *p1, void *p2, size_t n); /* in tcptrace.c */
#define memcpy(p1,p2,n) MemCpy(p1,p2,n)


/*
 * timeval compare macros
 */
#define tv_ge(lhs,rhs) (tv_cmp((lhs),(rhs)) >= 0)
#define tv_gt(lhs,rhs) (tv_cmp((lhs),(rhs)) >  0)
#define tv_le(lhs,rhs) (tv_cmp((lhs),(rhs)) <= 0)
#define tv_lt(lhs,rhs) (tv_cmp((lhs),(rhs)) <  0)
#define tv_eq(lhs,rhs) (tv_cmp((lhs),(rhs)) == 0)

/* handy constants */
#define US_PER_SEC 1000000	/* microseconds per second */
#define MS_PER_SEC 1000		/* milliseconds per second */


/*
 * Macros to simplify access to IPv4/IPv6 header fields
 */
#define PIP_VERS(pip) (((struct ip *)(pip))->ip_v)
#define PIP_ISV6(pip) (PIP_VERS(pip) == 6)
#define PIP_ISV4(pip) (PIP_VERS(pip) == 4)
#define PIP_V6(pip) ((struct ipv6 *)(pip))
#define PIP_V4(pip) ((struct ip *)(pip))
#define PIP_EITHERFIELD(pip,fld4,fld6) \
   (PIP_ISV4(pip)?(PIP_V4(pip)->fld4):(PIP_V6(pip)->fld6))
#define PIP_LEN(pip) (PIP_EITHERFIELD(pip,ip_len,ip6_lngth))

/*
 * Macros to simplify access to IPv4/IPv6 addresses
 */
#define ADDR_VERSION(paddr) ((paddr)->addr_vers)
#define ADDR_ISV4(paddr) (ADDR_VERSION((paddr)) == 4)
#define ADDR_ISV6(paddr) (ADDR_VERSION((paddr)) == 6)
struct ipaddr *IPV4ADDR2ADDR(struct in_addr *addr4);    
struct ipaddr *IPV6ADDR2ADDR(struct in6_addr *addr6);    

/*
 * Macros to check for congestion experienced bits
 */
#define IP_CE(pip) (((struct ip *)(pip))->ip_tos & IPTOS_CE)
#define IP_ECT(pip) (((struct ip *)(pip))->ip_tos & IPTOS_ECT)

/*
 * fixes for various systems that aren't exactly like Solaris
 */
#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif /* IP_MAXPACKET */

#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035
#endif /* ETHERTYPE_REVARP */
