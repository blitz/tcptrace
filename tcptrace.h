#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
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
#define MAX_TCP_PAIRS 30


typedef int PLOTTER;


struct last {
	/* parent pointer */
	struct stcp_pair *ptp;

	/* TCP information */
	u_long	ack;
	u_long	seq;
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

	/* plotter for this one */
	PLOTTER	plotter;
	char	*plotfile;

	/* host name letter(s) */
	char	*host_letter;
};

typedef u_int hash;

typedef struct {
	u_long	a_address;
	u_long	b_address;
	u_long	a_port;
	u_long	b_port;
	hash	hash;
} tcp_pair_addr;


struct stcp_pair {
	/* endpoint identification */
	tcp_pair_addr	addr_pair;

	/* connection information */
	char		*a_endpoint;
	char		*b_endpoint;
	struct timeval	first_time;
	struct timeval	last_time;
	u_long		packets;
	u_short		syn_count;
	u_short		fin_count;
	struct last	a2b;
	struct last	b2a;
};
typedef struct stcp_pair tcp_pair;


/* option flags */
extern int printem;
extern int plotem;
extern int debug;
extern int show_zero_window;
extern int show_rexmit;
extern int ignore_non_comp;


#define MAX_NAME 20

/* understood file formats */
#define SNOOP 1
#define NETM  2


/* external routine decls */
char *ether_ntoa();
void bzero();

/* global routine decls */
char *ts();
int is_netm();
int is_snoop();
int pread_netm();
int pread_snoop();
void dotrace();
void plotter_darrow();
void plotter_done();
void plotter_dtick();
PLOTTER plotter_init();
void plotter_line();
void plotter_text();
void plotter_uarrow();
void plotter_utick();
void printeth();     
void printpacket();     
void printtcp();     
void trace_done();
int Complete();
char *HostLetter();

