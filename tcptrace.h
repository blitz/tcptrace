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


typedef int PLOTTER;
extern PLOTTER topl;
extern PLOTTER frompl;
extern PLOTTER abpl;
extern PLOTTER bapl;


struct last {
	unsigned long	ack;
	unsigned long	seq;
	unsigned long	windowend;
	struct timeval	time;

	/* statistics added */
	unsigned	data_bytes;
	unsigned	data_pkts;
	unsigned	rexmit_bytes;
	unsigned	rexmit_pkts;
	unsigned	ack_pkts;
	unsigned	win_max;
	unsigned	win_tot;
	unsigned	win_zero_ct;
	unsigned	packets;
};


typedef struct {
	/* endpoint identification */
	unsigned long	a_address;
	unsigned long	b_address;
	unsigned short	a_port;
	unsigned short	b_port;

	/* connection information */
	char		*a_endpoint;
	char		*b_endpoint;
	struct timeval	first_time;
	struct timeval	last_time;
	int		packets;
	struct last	a2b;
	struct last	b2a;
} tcp_pair;


/* option flags */
extern int printem;
extern int debug;


#define MAX_NAME 20

/* understood file formats */
#define SNOOP 1
#define NETM  2


/* external routine decls */
char *ether_ntoa();
void bzero();

/* global routine decls */
char *ts();
void printtcp();     
void printpacket();     
void printeth();     
void plotter_done();
void plotter_init();
void trace_done();
void dotrace();
void plotter_darrow();
void plotter_dtick();
void plotter_line();
void plotter_uarrow();
void plotter_utick();
int is_netm();
int pread_netm();
int is_snoop();
int pread_snoop();

