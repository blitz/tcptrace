/* 
 * tcptrace.h - turn protocol monitor traces into xplot
 * 
 * Author:	Shawn Ostermann
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdarg.h>



/* type for plotting into a file */
typedef int PLOTTER;
#define NO_PLOTTER -1


/* type for a TCP sequence number, ACK, FIN, or SYN */
typedef u_long seqnum;

/* length of a segment */
typedef u_long seglen;

/* type for a quadrant number */
typedef u_char quadnum;  /* 1,2,3,4 */

/* type for a TCP port number */
typedef u_short portnum;

/* type for an IP address */
typedef struct in_addr ipaddr;

/* type for a timestamp */
typedef struct timeval timeval;

/* type for a Boolean */
typedef u_char Bool;
#define TRUE	1
#define FALSE	0

/* type for an internal file pointer */
typedef struct mfile MFILE;


/* test 2 IP addresses for equality */
#define IP_SAMEADDR(addr1,addr2) (((addr1).s_addr) == ((addr2).s_addr))

/* copy IP addresses */
#define IP_COPYADDR(toaddr,fromaddr) ((toaddr).s_addr = (fromaddr).s_addr)


typedef struct segment {
    seqnum	seq_firstbyte;	/* seqnumber of first byte */
    seqnum 	seq_lastbyte;	/* seqnumber of last byte */
    Bool	acked;		/* has it been acknowledged? */
    u_char	retrans;	/* retransmit count */
    timeval	time;	/* time the segment was sent */
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
    u_char	window_scale;

    /* statistics added */
    u_long	data_bytes;
    u_long	data_pkts;
    u_long	rexmit_bytes;
    u_long	rexmit_pkts;
    u_long	ack_pkts;
    u_long	win_max;
    u_long	win_min;
    u_long	win_tot;
    u_long	win_zero_ct;
    u_long	min_seq;
    u_long	packets;
    u_char	syn_count;
    u_char	fin_count;
    u_char	reset_count;  /* resets SENT */
    u_long	min_seg_size;
    u_long	max_seg_size;
    u_long	out_order_pkts;	/* out of order packets */

    /* RTT stats for singly-transmitted segments */
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
    u_long	rtt_amback;	/* ambiguous ACK */
    u_long	rtt_cumack;	/* segments only cumulativly ACKed */
    u_long	rtt_unkack;	/* unknown ACKs  ??? */
    u_long	rtt_dupack;	/* duplicate ACKs */
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
    double	thru_lastthru_i; /* last instantaneous throughput value */
    u_long	thru_bytes;	/* number of bytes this interval */
    u_long	thru_pkts;	/* number of packets this interval */
    double	thru_lastthru_t; /* last average throughput value */
    PLOTTER	thru_plotter;	/* throughput data dump file */
    timeval	thru_lasttime;	/* time of previous segment */
    
    /* Time Sequence Graph info for this one */
    PLOTTER	tsg_plotter;
    char	*tsg_plotfile;

    /* Dumped RTT samples */
    MFILE	*rtt_dump_file;

    /* RTT Graph info for this one */
    PLOTTER	rtt_plotter;
    u_long	rtt_lastrtt;
    timeval	rtt_lasttime;

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

    /* endpoint identification */
    tcp_pair_addrblock	addr_pair;

    /* connection information */
    char		*a_endpoint;
    char		*b_endpoint;
    timeval		first_time;
    timeval		last_time;
    u_long		packets;
    tcb			a2b;
    tcb			b2a;

    /* linked list of usage */
    struct stcp_pair *next;
};
typedef struct stcp_pair tcp_pair;

typedef struct tcphdr tcphdr;


/* maximum number of TCP pairs to maintain */
#define DEFAULT_MAX_TCP_PAIRS 1024
extern int max_tcp_pairs;

extern int num_tcp_pairs;	/* how many pairs are in use */
extern tcp_pair **ttp;		/* array of pointers to allocated pairs */


/* option flags */
extern int thru_interval;
extern Bool colorplot;
extern int debug;
extern Bool hex;
extern Bool ignore_non_comp;
extern Bool nonames;
extern Bool plotem;
extern Bool printbrief;
extern Bool printem;
extern Bool printticks;
extern Bool show_rexmit;
extern Bool print_rtt;
extern Bool graph_rtt;
extern Bool dump_rtt;
extern Bool show_out_order;
extern Bool show_zero_window;
extern Bool use_short_names;

extern timeval current_time;


#define MAX_NAME 20


/* external routine decls */
void *malloc(int);
void *MallocZ(int);
char *ether_ntoa();
void bzero(void *, int);
void bcopy(void *, void *,int);
void free(void *);
int finite(double);


/* global routine decls */
void trace_init();
void trace_done();
void seglist_init(tcb *);
void printpacket(int, int, void *, int, struct ip *);
void plotter_vtick(PLOTTER, timeval, u_long);
void plotter_utick(PLOTTER, timeval, u_long);
void plotter_uarrow(PLOTTER, timeval, u_long);
void plotter_tick(PLOTTER, timeval, u_long, char);
void plotter_text(PLOTTER, timeval, u_long, char *, char  *);
void plotter_temp_color(PLOTTER, char *color);
void plotter_rtick(PLOTTER, timeval, u_long);
void plotter_rarrow(PLOTTER, timeval, u_long);
void plotter_plus(PLOTTER, timeval, u_long);
void plotter_perm_color(PLOTTER, char *color);
void plotter_line(PLOTTER, timeval, u_long, timeval, u_long);
void plotter_larrow(PLOTTER, timeval, u_long);
void plotter_htick(PLOTTER, timeval, u_long);
void plotter_dtick(PLOTTER, timeval, u_long);
void plotter_dot(PLOTTER, timeval, u_long);
void plotter_done();
void plotter_dline(PLOTTER, timeval, u_long, timeval, u_long);
void plotter_diamond(PLOTTER, timeval, u_long);
void plotter_darrow(PLOTTER, timeval, u_long);
void plotter_box(PLOTTER, timeval, u_long);
void plotter_arrow(PLOTTER, timeval, u_long, char);
void plot_init();
void dotrace(int, struct ip *);
void dotrace();
void PrintTrace(tcp_pair *);
void PrintBrief(tcp_pair *);
void OnlyConn(int);
void IgnoreConn(int);
u_long elapsed(timeval, timeval);
int ConnReset(tcp_pair *);
int ConnComplete(tcp_pair *);
char *ts2ascii(timeval *);
char *ServiceName(portnum);
char *HostName(ipaddr);
char *HostLetter(u_int);
char *EndpointName(ipaddr,portnum);
PLOTTER new_plotter(tcb *plast, char *title, char *suffix);
int rexmit(tcb *, seqnum, seglen, Bool *);
void ack_in(tcb *, seqnum);
void DoThru(tcb *ptcb, int nbytes);
struct mfile *Mfopen(char *fname, char *mode);
int Mfprintf(MFILE *pmf, char *format, ...);
int Mvfprintf(MFILE *pmf, char *format, va_list ap);
int Mfclose(MFILE *pmf);
int Mfflush(MFILE *pmf);
void Minit();
struct tcp_options *ParseOptions(struct tcphdr *ptcp);


/* TCP flags macros */
#define SYN_SET(ptcp)((ptcp)->th_flags & TH_SYN)
#define FIN_SET(ptcp)((ptcp)->th_flags & TH_FIN)
#define ACK_SET(ptcp)((ptcp)->th_flags & TH_ACK)
#define RESET_SET(ptcp)((ptcp)->th_flags & TH_RST)
#define PUSH_SET(ptcp)((ptcp)->th_flags & TH_PUSH)
#define URGENT_SET(ptcp)((ptcp)->th_flags & TH_URG)


/* connection directions */
#define A2B 1
#define B2A -1

/* all we REALLY need is the IP and TCP headers, so don't copy	*/
/* any more than that...  IP header is <= (4*16) bytes and 	*/
/* the TCP header is at most (4*16)				*/
#define MAX_IP_PACKLEN ((4*16)+(4*16))


/*macros for maintaining the seqspace used for rexmit*/
#define QUADSIZE	(0x40000000)
#define QUADNUM(seq)	((seq>>30)+1)
#define IN_Q1(seq)	(QUADNUM(seq)==1)
#define IN_Q2(seq)	(QUADNUM(seq)==2)
#define IN_Q3(seq)	(QUADNUM(seq)==3)
#define IN_Q4(seq)	(QUADNUM(seq)==4)
#define FIRST_SEQ(quadnum)	(QUADSIZE*(quadnum-1))
#define LAST_SEQ(quadnum)	((QUADSIZE-1)*quadnum)
#define BOUNDARY(beg,fin) (QUADNUM((beg)) != QUADNUM((fin)))


/* physical layers currently understood					*/
#define PHYS_ETHER	1


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


/* RFC 1323 TCP options (not usually in tcp.h yet) */
#define	TCPOPT_WS	3	/* window scaling */
#define	TCPOPT_TS	8	/* timestamp */
struct tcp_options {
    short	mss;	/* maximum segment size 	*/
    char	ws;	/* window scale (1323) 		*/
    long	tsval;	/* Time Stamp Val (1323)	*/
    long	tsecr;	/* Time Stamp Echo Reply (1323)	*/
};



/*
 * File extensions to use
 *
 */
#define RTT_DUMP_FILE_EXTENSION		"rttraw"
#define RTT_GRAPH_FILE_EXTENSION	"rtt"
#define PLOT_FILE_EXTENSION		"xpl"
#define THROUGHPUT_FILE_EXTENSION	"tput"
