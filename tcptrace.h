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



/* maximum number of TCP pairs to maintain */
#define DEFAULT_MAX_TCP_PAIRS 256
extern int max_tcp_pairs;

typedef int PLOTTER;
#define NO_PLOTTER -1


/* type for a TCP sequence number, ACK, FIN, or SYN */
typedef u_long seqnum;

/* type for a TCP port number */
typedef u_short portnum;

/* type for an IP address */
typedef struct in_addr ipaddr;


/* test 2 IP addresses for equality */
#define IP_SAMEADDR(addr1,addr2) (((addr1).s_addr) == ((addr2).s_addr))

/* copy IP addresses */
#define IP_COPYADDR(toaddr,fromaddr) ((toaddr).s_addr = (fromaddr).s_addr)


typedef struct seg_rec {
    seqnum	ackedby;	/* which ACK covers this segment */
    seqnum	seq;		/* sequence number */
    u_long	retrans;	/* retransmit count */
    struct	timeval	time;	/* time the segment was sent */
    struct	seg_rec	*next;	/* next in list */
    struct	seg_rec	*prev;	/* prev in list */
} seg_rec;

typedef struct seg_acked {
    u_long	beg;
    u_long 	sent_end;
    struct  seg_acked *next;
    struct  seg_acked *prev;
} seg_acked;

typedef struct quadrant {
    seg_acked 	*f_ack;
    seg_acked   *l_ack;
    u_long 	quad_end;
    int 	full;
    struct quadrant *next;
    struct quadrant *prev;
} quadrant;

typedef struct seqspace {
    u_long 	begin;
    u_long 	end;
    quadrant 	*q1;
    quadrant 	*q2;
    quadrant 	*q3;
    quadrant 	*q4;
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
    struct	timeval	time;

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
    u_long	ooo_pkts;	/* out of order packets */

    /* information for RTO tracking */
    seg_rec	seglist_head;
    seg_rec	seglist_tail;
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
    u_long	rtt_redack;	/* redundant ACKs */
    /* retransmission information */
    seqspace    *ss;		/* the sequence space*/
    u_long	retr_max;	/* maximum retransmissions ct */
    u_long	retr_min_tm;	/* minimum retransmissions time */
    u_long	retr_max_tm;	/* maximum retransmissions time */
    double	retr_tm_sum;	/* for averages */
    double	retr_tm_sum2;	/* sum of squares, for stdev */
    u_long	retr_tm_count;	/* for averages */

    /* Time Sequence Graph info for this one */
    PLOTTER	tsg_plotter;
    char	*tsg_plotfile;

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
    int		ignore_pair;

    /* endpoint identification */
    tcp_pair_addrblock	addr_pair;

    /* connection information */
    char		*a_endpoint;
    char		*b_endpoint;
    struct timeval	first_time;
    struct timeval	last_time;
    u_long		packets;
    tcb			a2b;
    tcb			b2a;

    /* linked list of usage */
    struct stcp_pair *next;
};
typedef struct stcp_pair tcp_pair;

typedef struct tcphdr tcphdr;


/* option flags */
extern int colorplot;
extern int debug;
extern int dortt;
extern int hex;
extern int ignore_non_comp;
extern int nonames;
extern int plotem;
extern int printbrief;
extern int printem;
extern int printticks;
extern int show_rexmit;
extern int show_zero_window;


#define MAX_NAME 20


/* external routine decls */
void *malloc(int);
char *ether_ntoa();
void bzero(void *, int);
void bcopy(void *, void *,int);
void free(void *);
int finite(double);


/* global routine decls */
void trace_init();
void trace_done();
void seglist_init(tcb *);
void printpacket(struct timeval, int, int, void *, int, struct ip *);
void plotter_vtick(PLOTTER, struct timeval, u_long);
void plotter_utick(PLOTTER, struct timeval, u_long);
void plotter_uarrow(PLOTTER, struct timeval, u_long);
void plotter_tick(PLOTTER, struct timeval, u_long, char);
void plotter_text(PLOTTER, struct timeval, u_long, char *, char  *);
void plotter_temp_color(PLOTTER, char *color);
void plotter_rtick(PLOTTER, struct timeval, u_long);
void plotter_rarrow(PLOTTER, struct timeval, u_long);
void plotter_plus(PLOTTER, struct timeval, u_long);
void plotter_perm_color(PLOTTER, char *color);
void plotter_line(PLOTTER, struct timeval, u_long, struct timeval, u_long);
void plotter_larrow(PLOTTER, struct timeval, u_long);
void plotter_htick(PLOTTER, struct timeval, u_long);
void plotter_dtick(PLOTTER, struct timeval, u_long);
void plotter_dot(PLOTTER, struct timeval, u_long);
void plotter_done();
void plotter_dline(PLOTTER, struct timeval, u_long, struct timeval, u_long);
void plotter_diamond(PLOTTER, struct timeval, u_long);
void plotter_darrow(PLOTTER, struct timeval, u_long);
void plotter_box(PLOTTER, struct timeval, u_long);
void plotter_arrow(PLOTTER, struct timeval, u_long, char);
void plot_init();
void dotrace(struct timeval, int, struct ip *);
void dotrace();
void calc_rtt(tcb *, struct timeval, struct tcphdr *, struct ip *);
void PrintTrace(tcp_pair *);
void PrintBrief(tcp_pair *);
void OnlyConn(int);
void IgnoreConn(int);
u_long elapsed(struct timeval, struct timeval);
int ConnReset(tcp_pair *);
int ConnComplete(tcp_pair *);
char *ts2ascii(struct timeval *);
char *ServiceName(portnum);
char *HostName(ipaddr);
char *HostLetter(u_int);
char *EndpointName(ipaddr,portnum);
PLOTTER new_plotter(tcb *plast, char *title);
int rexmit(seqspace *, u_long, u_long, u_int *);


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
/* any more than that...  IP header is <= 20 bytes and 		*/
/* the TCP header is 20 (don't use options here)		*/
#define MAX_IP_PACKLEN 40


/*macros for maintaining the seqspace used for rexmit*/
#define SEQSPACE_SIZE	0xffffffff
#define QUADSIZE	(SEQSPACE_SIZE/4)
#define SEQTEST(seq)	((seq>>30)+1)
#define IN_Q1(seq)	(SEQTEST(seq)==1)
#define IN_Q2(seq)	(SEQTEST(seq)==2)
#define IN_Q3(seq)	(SEQTEST(seq)==3)
#define IN_Q4(seq)	(SEQTEST(seq)==4)


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
