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



/* maximum number of TCP pairs to maintain */
#define DEFAULT_MAX_TCP_PAIRS 256
extern int max_tcp_pairs;

/* number of plotters to use */
#define DEFAULT_MAX_PLOTTERS (2*MAX_TCP_PAIRS)
extern int max_plotters;

typedef int PLOTTER;
#define NO_PLOTTER -1


typedef struct seg_rec {
    u_long	ackedby;	/* which ACK covers this segment */
    u_long	seq;		/* sequence number */
    u_long	retrans;	/* retransmit count */
    struct	timeval	time;	/* time the segment was sent */
    struct	seg_rec	*next;	/* next in list */
    struct	seg_rec	*prev;	/* prev in list */
} seg_rec;


typedef struct tcb {
    /* parent pointer */
    struct stcp_pair *ptp;
    struct tcb	*ptwin;

    /* TCP information */
    u_long	ack;
    u_long	seq;
    u_long	syn;
    u_long	fin;
    u_long	windowend;
    struct	timeval	time;

    /* statistics added */
    u_long	data_bytes;
    u_long	data_pkts;
    u_long	rexmit_bytes;
    u_long	rexmit_pkts;
    u_long	ack_pkts;
    u_long	win_max;
    u_long	win_tot;
    u_long	win_zero_ct;
    u_long	min_seq;
    u_long	packets;
    u_char	syn_count;
    u_char	fin_count;

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
    u_long	retr_max;	/* maximum retransmissions ct */
    u_long	retr_min_tm;	/* minimum retransmissions time */
    u_long	retr_max_tm;	/* maximum retransmissions time */
    double	retr_tm_sum;	/* for averages */
    double	retr_tm_sum2;	/* sum of squares, for stdev */
    u_long	retr_tm_count;	/* for averages */

    /* plotter for this one */
    PLOTTER	plotter;
    char	*plotfile;

    /* host name letter(s) */
    char	*host_letter;
} tcb;

typedef u_short hash;

typedef struct {
	u_long	a_address;
	u_long	b_address;
	u_long	a_port;
	u_long	b_port;
	hash	hash;
} tcp_pair_addr;


struct stcp_pair {
    /* are we ignoring this one?? */
    int		ignore_pair;

    /* endpoint identification */
    tcp_pair_addr	addr_pair;

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
    struct stcp_pair *prev;
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

/* understood file formats */
#define SNOOP 1
#define NETM  2
#define TCPDUMP 3


/* external routine decls */
char *malloc(int);
char *ether_ntoa();
void bzero(void *,int);
void free(void *);


/* global routine decls */
char *ts();
unsigned long elapsed();

int is_tcpdump();
int is_netm();
int is_snoop();

int pread_tcpdump();
int pread_netm();
int pread_snoop();

void dotrace();
void plotter_darrow();
void plotter_done();
void plotter_dtick();
PLOTTER new_plotter();
void plotter_line();
void plotter_text();
void plotter_uarrow();
void plotter_utick();
void plotter_diamond();
void plotter_box();
void plotter_temp_color(PLOTTER,char*);
void plotter_perm_color(PLOTTER,char*);
void printeth();     
void printpacket();     
void printtcp();     
void trace_done();
void trace_init();
void plot_init();
void OnlyConn();
void IgnoreConn();
void calc_rtt();
void seglist_init();
int Complete();
char *HostLetter();
char *EndpointName();
void PrintBrief(tcp_pair *);
void PrintTrace(tcp_pair *ptp);


/* common defines */
#define TRUE 1
#define FALSE 0
#define OK 0     
#define SYSERR -1


/* TCP flags macros */
#define SYN_SET(ptcp)((ptcp)->th_flags & TH_SYN)
#define FIN_SET(ptcp)((ptcp)->th_flags & TH_FIN)
#define ACK_SET(ptcp)((ptcp)->th_flags & TH_ACK)
#define RESET_SET(ptcp)((ptcp)->th_flags & TH_RST)


/* connection directions */
#define A2B 1
#define B2A -1


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

