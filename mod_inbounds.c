/*
 * Copyright (c) 1994-2004
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
 * 
 *              Manikantan Ramadas
 *              mramadas@irg.cs.ohiou.edu
 */


#ifdef LOAD_MODULE_INBOUNDS

#include "tcptrace.h"
#include <fcntl.h>
#include <limits.h>
#include "mod_inbounds.h"

static int inc_cnt=0;
static int dointer_cnt=0;
static int udp_delconn_cnt=0;

// info kept for tcp packets:
struct inbounds_tcp_conn_info 
{
     timeval first_time; // time of the connection's first packet 
     timeval first_data_time; // time of the connection's first data packet
     timeval last_time;	// time of the connection's last packet
     timeval last_data_time; // time of the connection's last data packet
     
     Bool had_data;  
     Bool closed; // has the connection been closed ?
     Bool new; // is the connection new ?
     
     tcp_pair_addrblock	addr_pair;
     tcp_pair *ptp;
     
     u_long a_pkt;	/* number of packets from a to b within
			 the time interval */
     u_long b_pkt; 
     u_long a_byte;	/* number of bytes from a to b within 
			 the time interval */ 
     u_long b_byte;
     
     u_int qNum;
     u_int aNum;
     u_long qSum;
     u_long aSum;
     timeval q2aIdle;
     timeval a2qIdle;
     Bool dir;	/* 0 - question, 1 - answer */
     u_long burst_bytes;
     
     /* for determining bursts */
     tcb *tcb_lastdata;
     
     struct inbounds_tcp_conn_info *prev; /* pointer to the next connection */
     struct inbounds_tcp_conn_info *next; /* pointer to the next connection */
}; 

typedef struct inbounds_tcp_conn_info itcinfo;

/* structure for udp connections */
struct inbounds_udp_conn_info 
{     
     timeval first_time; // time of the connection's first packet 
     timeval last_time; // time of the connection's last packet
     
     Bool closed; // has the connection been closed ?
     Bool new; // is the connection new ?
     
     udp_pair_addrblock addr_pair;
     udp_pair *pup;
     
     u_long a_pkt;  /* number of packets from a to b within
			    the time interval */
     u_long b_pkt;
     u_long a_byte; /* number of bytes from a to b within
			    the time interval */
     u_long b_byte;
     
     u_int qNum;
     u_int aNum;
     u_long qSum;
     u_long aSum;
     timeval q2aIdle;
     timeval a2qIdle;
     
     Bool dir;    /* 0 - question, 1 - answer */
     
     struct inbounds_udp_conn_info *prev; /* pointer to the next connection */
     struct inbounds_udp_conn_info *next; /* pointer to the next connection */
};

typedef struct inbounds_udp_conn_info iucinfo;

struct inbounds_info 
{     
     // times of the last network statistics as it should appear in ideally
     // for TCP and UDP:
     timeval last_tcp_scheduled_time;
     timeval last_udp_scheduled_time;
     // times when the last network stats actually happened for TCP and UDP:
     timeval last_tcp_actual_time;
     timeval last_udp_actual_time;    
     
     itcinfo *tcp_conn_head;	/* head of the list of tcp connections */
     itcinfo *tcp_conn_tail;	/* tail of the list of tcp connections */
     
     u_short tcp_new_conn;	/* number of new connections within the 
				 time interval */
     u_short tcp_total_conn; // number of currect active connections
     
     /* this info is for UDP conn */
     iucinfo *udp_conn_head; /* head of the list of udp connections */
     iucinfo *udp_conn_tail; /* tail of the list of udp connections */
     
     u_short udp_new_conn; /* number of new connections within the
			      time interval */
     u_short udp_total_conn; /* number of currect udp active connections */
     
};

typedef struct inbounds_info iinfo;

struct protocol 
{
     u_char ip_p;
     u_llong count;
     struct protocol *next;
};


#define INBOUNDS_TCP_UPDATE_INTERVAL 60
#define INBOUNDS_UDP_UPDATE_INTERVAL 60

#define INBOUNDS_DEBUG 0 /* debug flag */

#define TCB_CACHE_A2B 0
#define TCB_CACHE_B2A 1

#define UDPHDR_LEN 8
#define UDP_A2B 0
#define UDP_B2A 1

/* global variables */
static iinfo *mod_info;

static u_llong tcp_packets = 0;
static u_llong udp_packets = 0;
static u_llong nontcpudp_packets = 0;
static struct protocol *plist = NULL;

/* local routines */
static void AllTCPInteractivity(void);
static void TCPInteractivity(itcinfo *conn);

static void AllUDPInteractivity(void);
static void UDPInteractivity(iucinfo *conn);
static void PrintUDPCMsg(iucinfo *);
static void ClosedUDPConn();

static Bool IsNewBurst(itcinfo *conn, tcb *ptcb, struct tcphdr *tcp, Bool dir);

static void ipCheck(struct ip *pip, void *plast);
static void tcpCheck(struct ip *pip, tcp_pair *ptcp, void *plast);
static void udpCheck(struct ip *pip, udp_pair *pup, void *plast);

static itcinfo *Makeitcinfo(void);
static iucinfo *Makeiucinfo(void);
static void Freeitcinfo(itcinfo *);
static void Freeiucinfo(iucinfo *);

/* declarations of memory management functions for the module */

static long itcinfo_pool = -1;
static long iucinfo_pool = -1;

/* tcp packet */

static itcinfo *
     Makeitcinfo(
		void)
{
     itcinfo *ptr = NULL;
     
     if (itcinfo_pool < 0) {
	  itcinfo_pool = MakeMemPool(sizeof(itcinfo), 0);
     }
     
     ptr = PoolMalloc(itcinfo_pool, sizeof(itcinfo));
     return ptr;
}

/* udp packet */

static iucinfo *
     Makeiucinfo(
		 void)
{
     iucinfo *ptr = NULL;

     if (iucinfo_pool < 0) {	  
	  iucinfo_pool = MakeMemPool(sizeof(iucinfo), 0);
     }
     
     ptr = PoolMalloc(iucinfo_pool, sizeof(iucinfo));
     return ptr;
}


static void
     Freeitcinfo(
		itcinfo *ptr)
{
     PoolFree(itcinfo_pool, ptr);
}

static void
     Freeiucinfo(
		 iucinfo *ptr)
{
     PoolFree(iucinfo_pool, ptr);
}

/* Usage message for using the INBOUNDS module */

void
     inbounds_usage(void)
{
     printf("Use -xinbounds to call INBOUNDS and add -u for UDP conn. analysis\
		 \n");
}

int
     inbounds_init(
		   int argc,
		   char *argv[])
{
     int i, fd;
     int enable=0;
     
     
     /* look for "-xinbounds" */
     for (i=1; i < argc; ++i) {
	  if (!argv[i])
	       continue;  /* argument already taken by another module... */
	  
	  if (strncmp(argv[i],"-x",2) == 0) {
	       if (strncasecmp(argv[i]+2,"inbounds", 8) == 0) {
		    /* I want to be called */
		    enable = 1;
		    // We *are* running the program in real-time mode
		    run_continuously=TRUE;

		    if(INBOUNDS_DEBUG)
			 fprintf(stderr, "mod_inbounds: Capturing traffic\n");
		    argv[i] = NULL;
	       }   
	  }	  
     }
     
     if (!enable)
	  return(0);	/* don't call me again */
     
     mod_info = (iinfo *)malloc(sizeof(iinfo));
     mod_info->last_tcp_scheduled_time = current_time;
     mod_info->last_tcp_actual_time = current_time;
     mod_info->last_udp_scheduled_time = current_time;
     mod_info->last_udp_actual_time = current_time;

     mod_info->tcp_conn_head = NULL;
     mod_info->tcp_conn_tail = NULL;
     mod_info->tcp_new_conn = 0;
     mod_info->tcp_total_conn = 0;
     mod_info->udp_conn_head = NULL;
     mod_info->udp_conn_tail = NULL;
     mod_info->udp_new_conn = 0;
     mod_info->udp_total_conn = 0;
     resolve_ipaddresses = FALSE;
     resolve_ports = FALSE;
     
     return(1);	/* TRUE means call other inbounds routines later */
}


void
     inbounds_done(void)
{
     struct protocol *pp;
     
     // When we are simulating attack, i.e feed just the attack to this module
     // un-domment the following section to wash out the attack at the end
     // to produce 'U' and 'C' messages.
     if(do_udp) {
//	  iucinfo *udp_conn;
	  ClosedUDPConn();
/*	  for (udp_conn=mod_info->udp_conn_head; udp_conn!=NULL;
	       udp_conn=udp_conn->next) {
	       if(!udp_conn->closed) {
		    // Assume that its been UDP_REMOVE_LIVE_CONN_INTERVAL
		    // since we had the last message on this connection
		    current_time.tv_sec=udp_conn->last_time.tv_sec+
			 UDP_REMOVE_LIVE_CONN_INTERVAL;
		    UDPInteractivity(udp_conn);
		    udp_conn->closed=TRUE;
		    PrintUDPCMsg(udp_conn);
	       }
	  }*/
     }
     
#ifdef HAVE_LONG_LONG
     fprintf(stderr, "\nINBOUNDS: TCP packets - %llu\n", tcp_packets);
     fprintf(stderr, "INBOUNDS: UDP packets - %llu\n", udp_packets);
     fprintf(stderr, "INBOUNDS: other packets - %llu\n", nontcpudp_packets);
#else
     fprintf(stderr, "\nINBOUNDS: TCP packets - %lu\n", tcp_packets);
     fprintf(stderr, "INBOUNDS: UDP packets - %lu\n", udp_packets);
     fprintf(stderr, "INBOUNDS: other packets - %lu\n", nontcpudp_packets);
#endif
     
     for (pp = plist; pp; pp = pp->next) {
#ifdef HAVE_LONG_LONG
	  fprintf(stderr, "\tprotocol: %3u, number: %llu\n", pp->ip_p, pp->count);
#else
	  fprintf(stderr, "\tprotocol: %3u, number: %lu\n", pp->ip_p, pp->count);
#endif
     }
     fprintf(stderr, "\n");
}

/* for a new TCP connection */

void *
     inbounds_tcp_newconn( 
		       tcp_pair *ptp)
{
     itcinfo *newConn = Makeitcinfo();
     
     if (mod_info->last_tcp_scheduled_time.tv_sec == 0) {
	  mod_info->last_tcp_scheduled_time = current_time;
	  mod_info->last_tcp_actual_time = current_time;
     }
     
     newConn->first_time = current_time;
     newConn->first_data_time.tv_sec = 0;
     newConn->first_data_time.tv_usec = 0;
     newConn->last_time = current_time;
     newConn->last_data_time.tv_sec = 0;
     newConn->last_data_time.tv_usec = 0;
     newConn->had_data = FALSE;
     newConn->new = TRUE;
     newConn->closed = FALSE;
     newConn->addr_pair = ptp->addr_pair;
     newConn->ptp = ptp;
     newConn->a_pkt = 0;
     newConn->b_pkt = 0;
     newConn->a_byte = 0;
     newConn->b_byte = 0;
     newConn->next = NULL;
     newConn->prev = NULL;
     newConn->tcb_lastdata = &ptp->a2b;
     newConn->qNum = 0;
     newConn->aNum = 0;
     newConn->qSum = 0;
     newConn->aSum = 0;
     newConn->q2aIdle.tv_sec = 0; newConn->q2aIdle.tv_usec = 0;
     newConn->a2qIdle.tv_sec = 0; newConn->a2qIdle.tv_usec = 0;
     newConn->dir = TCB_CACHE_A2B;
     
     if (mod_info->tcp_conn_head != NULL) {
	  mod_info->tcp_conn_tail->next = newConn;
	  newConn->prev = mod_info->tcp_conn_tail;
	  mod_info->tcp_conn_tail = newConn;
     }
     else { /* the list is empty */
	  mod_info->tcp_conn_head = newConn;
	  mod_info->tcp_conn_tail = newConn;
     }
     mod_info->tcp_total_conn++;
     
     return newConn;
}

/* delete TCP connection */

void
     inbounds_tcp_deleteconn(
			 tcp_pair *ptp,	/* info I have about this connection */
			 void *mod_data)	/* module specific info for this conn*/
{
     itcinfo *conn = mod_data;
     Bool   done = FALSE;
     
     if (conn == mod_info->tcp_conn_head) {
	  mod_info->tcp_conn_head = mod_info->tcp_conn_head->next;
	  if (mod_info->tcp_conn_head) {
	       mod_info->tcp_conn_head->prev = NULL;
	  }
	  done = TRUE;
     }
     if (conn == mod_info->tcp_conn_tail) {
	  mod_info->tcp_conn_tail = mod_info->tcp_conn_tail->prev;
	  if (mod_info->tcp_conn_tail) {
	       mod_info->tcp_conn_tail->next = NULL;
	  }
	  done = TRUE;
     }
     if (!done) {
	  conn->prev->next = conn->next;
	  conn->next->prev = conn->prev;
     }
     Freeitcinfo(conn);
     return;
}

/* For TCP packets
 * If this packet opens a new connections then output the 'O' message.
 * Grab the information required to generate the update messages. 
 */

void
     inbounds_tcp_read(
		   struct ip *pip,	/* the packet */
		   tcp_pair *ptp,	/* info I have about this connection */
		   void *plast,	        /* past byte in the packet */
		   void *mod_data)	/* module specific info for this 
					 connection */
{
     char *tmp;
     struct tcphdr *tcp;/* TCP header information */
     int data_len = 0;  /* length of the data cargo in the packet */
     itcinfo *conn = mod_data;
     timeval delta;
     
     tcb *ptcb;
     int dir;
     
     int status = 0;
     double dtime = 0;
     
     ++tcp_packets;
     
#ifdef _MONITOR
     ipCheck(pip, plast);
     tcpCheck(pip, ptp, plast);
#endif
     
     /* first, discard any connections that we aren't interested in. */
     /* That means that pmodstruct is NULL */
     if (conn == NULL) {
	  return;
     }
     
     if (0) {
	  printf("hash %i\t\tclosed %i, a2bfin %i, b2afin %i\n", 
		 ptp->addr_pair.hash, conn->closed, 
		 ptp->a2b.fin_count, ptp->b2a.fin_count);
	  fflush(stdout);
     }
     
     if (conn->new) {
	  if (ptp->a2b.syn_count > 0) {
	       status = 0;
	  } else if (ptp->b2a.syn_count > 0) {
	       status = 0; 
	       conn->dir = TCB_CACHE_B2A;
	  } else {
	       status = 1;
	       if (conn->addr_pair.a_port < conn->addr_pair.b_port) {
		    conn->dir = TCB_CACHE_B2A;
	       }
	  }
	  dtime = current_time.tv_sec + (current_time.tv_usec / 1000000.0);
	  if ((tmp=(char*)calloc(MAX_LINE_LEN,sizeof(char)))==NULL) {
	       fprintf(stderr,"mod_inbounds: calloc() failed\n");
	       exit(-1);
	  }
	  sprintf(tmp, "O %.6f TCP %s %s %i\n", 
		  dtime, ptp->a_endpoint, ptp->b_endpoint, status);
	  
	  if (fwrite(tmp, strlen(tmp), 1, stdout) <= 0) {
	       fprintf(stderr, "Couldn't write to stdout\n");
	       exit(1);
	  }
	  
	  fflush(stdout);
	  free(tmp);     
	  conn->new = FALSE;
     }
     
     /* Setting a pointer to the beginning of the TCP header */
#ifdef IP_IPVHL
     tcp = (struct tcphdr *) ((char *)pip + (4 * (pip->ip_vhl & 0x0f)));
#else
     tcp = (struct tcphdr *) ((char *)pip + (4 * pip->ip_hl));
#endif
     
     /* calculate the amount of user data */
     data_len = ntohs(pip->ip_len) -	/* size of entire IP packet (and IP header) */
#ifdef IP_IPVHL
	  (4 * (pip->ip_vhl & 0x0f)) -	/* less the IP header */
#else
	  (4 * pip->ip_hl) -	/* less the IP header */
#endif
#ifdef TCP_THXOFF
	  (4 * (tcp->th_xoff >> 4));	/* less the TCP header */
#else
     (4 * tcp->th_off);	/* less the TCP header */
#endif
     
     /* see which of the 2 TCB's this goes with */
     if (ptp->addr_pair.a_port == ntohs(tcp->th_sport)) {
	  ptcb = &ptp->a2b;
	  dir = TCB_CACHE_A2B;
     } else {
	  ptcb = &ptp->b2a;
	  dir = TCB_CACHE_B2A;
     }
     
     if (0)
	  printf("INBOUNDS: %s <-> %s; dir = %i ", 
		 ptp->a_endpoint, ptp->b_endpoint, dir);
     
     if (debug > 2) {  
	  printf("conn %s<->%s, my dir=%i, packet's dir=%i; IsNewBurst=", 
		 ptp->a_endpoint, ptp->b_endpoint, conn->dir, dir);
     }
     if (data_len > 0) {
	  if (tv_lt(conn->first_data_time, conn->first_time)) {
	       conn->first_data_time = current_time;
	       conn->had_data = TRUE;
	  }
     }
     
     /* see if it's a new burst */
     if (!conn->closed) {
	  if (((data_len > 0) && (IsNewBurst(conn, ptcb, tcp, dir))) ||
	      ((FIN_SET(tcp)) && (FinCount(ptp) == 1)) ||
	      (RESET_SET(tcp))) {
	       
	       delta = current_time;
	       tv_sub(&delta, conn->last_data_time);
	       
	       if (FIN_SET(tcp) || RESET_SET(tcp)) {
		    if (conn->had_data) {
			 if (conn->dir == 0) { /* we had a question before */
			      conn->dir = 1;
			      conn->qNum++;
			      conn->qSum += conn->burst_bytes;
			      tv_add(&conn->q2aIdle, delta);
			 }
			 else { /* we had an answer before */
			      conn->dir = 0; /* we have question */
			      conn->aNum++;    /* number of complete answers */
			      conn->aSum += conn->burst_bytes;
			      tv_add(&conn->a2qIdle, delta); 
			 }
		    }
	       }
	       else {
		    if (dir == TCB_CACHE_A2B) {
			 conn->dir = 0; /* we have question */
			 conn->aNum++;    /* number of complete answers */
			 conn->aSum += conn->burst_bytes;
			 tv_add(&conn->a2qIdle, delta); 
		    }
		    else {
			 conn->dir = 1;
			 conn->qNum++;
			 conn->qSum += conn->burst_bytes;
			 tv_add(&conn->q2aIdle, delta);
		    }
	       }
	       conn->burst_bytes = 0;
	       
	       if (0) {
		    fprintf(stderr, "%.6f switching direction from %s to %s, idle time is %.6f\n",
			    current_time.tv_sec + (current_time.tv_usec / 1000000.0),
			    (conn->dir == 0) ? "answer" : "question",
			    (conn->dir == 0) ? "question" : "answer", 
			    delta.tv_sec + (delta.tv_usec / 100000.0));
	       }
	       
	       if (debug > 2) 
		    printf("true ");
	  }
     }
     
     if (data_len > 0) {
	  conn->last_data_time = current_time;
	  conn->burst_bytes += data_len;
     }
     conn->last_time = current_time;
     
     status = 0;
     if (!conn->closed) {
	  if ((FinCount(ptp) >= 1) || (ConnReset(ptp))) {
	       if (0) {
		    fprintf(stderr, "number of questions: %i, number of answers: %i\n", 
	           conn->qNum, conn->aNum);
	       }
	       TCPInteractivity(conn);
	       if (dtime == 0) {
		    dtime = current_time.tv_sec + (current_time.tv_usec / 1000000.0);
	       }

	       if ((ptp->a2b.reset_count >=1) || (ptp->b2a.reset_count >= 1)) {
		    status = 1;
	       }
	       if ((tmp=(char*)calloc(MAX_LINE_LEN,sizeof(char)))==NULL) {
		    fprintf(stderr,"mod_inbounds: calloc() failed\n");
		    exit(-1);
	       }	   
	       sprintf(tmp, "C %.6f TCP %s %s %i\n",
		       dtime, ptp->a_endpoint, ptp->b_endpoint, status);
	       
	       if (fwrite(tmp, strlen(tmp), 1, stdout) <= 0) {
		    fprintf(stderr, "mod_inbounds: couldn't write to stdout\n"
			    );
		    exit(1);
	       }
	       fflush(stdout);
	       free(tmp);
	       conn->closed = TRUE;
	  }
     }
     
     if ((elapsed(mod_info->last_tcp_scheduled_time, current_time) / 1000000.0)
	 >= INBOUNDS_TCP_UPDATE_INTERVAL) {
	  AllTCPInteractivity();
     }
}

/* for new UDP connections */
void *
     inbounds_udp_newconn(
			  udp_pair *pup)
{
     iucinfo *newConn = Makeiucinfo();
     
     inc_cnt++;
     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds:udp_newconn() \n");
     
     if (mod_info->last_udp_scheduled_time.tv_sec == 0) {
	  mod_info->last_udp_scheduled_time = current_time;
	  mod_info->last_udp_actual_time = current_time;
     }
     
     newConn->first_time = current_time;
     newConn->last_time = current_time;
     newConn->new = TRUE;
     newConn->closed = FALSE;
     newConn->addr_pair = pup->addr_pair;
     newConn->pup = pup;
     newConn->a_pkt = 0;
     newConn->b_pkt = 0;
     newConn->a_byte = 0;
     newConn->b_byte = 0;
     newConn->next = NULL;
     newConn->prev = NULL;
     newConn->qNum = 0;
     newConn->aNum = 0;
     newConn->qSum = 0;
     newConn->aSum = 0;
     
     // If this field remains -1, it means 
     // q2aIdle could not be calculated for 
     // INBOUNDS_UDP_UPDATE_INTERVAL.
     // In that case, we shall print out 
     // q2aIdle as = INBOUNDS_UDP_UPDATE_INTERVAL, i.e. q2a duration is max.
     newConn->q2aIdle.tv_sec = -1;
     newConn->q2aIdle.tv_usec = 0;
     newConn->a2qIdle.tv_sec = -1;
     newConn->a2qIdle.tv_usec = 0;
     newConn->dir = UDP_A2B;
     
     if (mod_info->udp_conn_head != NULL) {
	  mod_info->udp_conn_tail->next = newConn;
	  newConn->prev = mod_info->udp_conn_tail;
	  mod_info->udp_conn_tail = newConn;
     }
     else {
	  mod_info->udp_conn_head = newConn;
	  mod_info->udp_conn_tail = newConn;
     }
     mod_info->udp_total_conn++;
     
     return newConn;
}

/* This function is not invoked by tcptrace currently and is here mostly
 * for the sake of completeness. You may need to fix the module definition
 * in modules.h and fix tcptrace.c/trace.c to make sure this function gets 
 * invoked (if you need this functionality, of course) - Mani, 4 Mar 2004.
 */

/* delete timedout UDP connections */
void
     inbounds_udp_deleteconn(
			     udp_pair *pup, // info I have about this conn.
			     void *mod_data)// module specific info for this
	                                    //conn.
{
     iucinfo *conn = mod_data;
     Bool   done = FALSE;
     
     udp_delconn_cnt++;
     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds:udp_deleteconn() \n");
     
     if (conn == mod_info->udp_conn_head) {
	  mod_info->udp_conn_head = mod_info->udp_conn_head->next;
	  if (mod_info->udp_conn_head) {
	       mod_info->udp_conn_head->prev = NULL;
	  }
	  done = TRUE;
     }
     if (conn == mod_info->udp_conn_tail) {
	  mod_info->udp_conn_tail = mod_info->udp_conn_tail->prev;
	  if (mod_info->udp_conn_tail) {
	       mod_info->udp_conn_tail->next = NULL;
	  }
	  done = TRUE;
     }
     
     if (!done) {
	  conn->prev->next = conn->next;
	  conn->next->prev = conn->prev;
     }
     
     if(!conn->closed) {
	  UDPInteractivity(conn);
	  PrintUDPCMsg(conn);
     }
     
     Freeiucinfo(conn);
     return;
}

/* For UDP packets
 * If this packet opens a new connections then output the 'O' message.
 * Grab the information required to generate the update messages
 */

void 
inbounds_udp_read(
		  struct ip *pip, 
		  udp_pair *pup, 
		  void *plast, 
		  void *mod_data)
{
     char *tmp;
     struct udphdr *udp;          /* UDP header information */
     int           data_len = 0;  /* length of the data cargo in the packet */
     iucinfo       *conn = mod_data;
     timeval       delta;
     
     int dir;
     
     int status = 0;
     double dtime = 0;
     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds:udp_read() \n");
     
     ++udp_packets;
     
     
#ifdef _MONITOR
     ipCheck(pip, plast);
     udpCheck(pip, pup, plast);
#endif
     
     /* first, discard any connections that we aren't interested in. */
     /* That means that pmodstruct is NULL */
     if (conn == NULL || pup == NULL) {
	  if(INBOUNDS_DEBUG)
	       printf("mod_inbounds:udp_read() conn is NULL or pup \n");
	  return;
     }
     
     if (conn->new) {
	  if(INBOUNDS_DEBUG)
	       printf("mod_inbounds:udp_read() This is new connection\n");
	  
	  dtime = current_time.tv_sec + (current_time.tv_usec / 1000000.0);
	  if(INBOUNDS_DEBUG) { 
	       printf("dtime: %.6f \n",dtime);
	       printf("pup->a_endpoint: %s \n",pup->a_endpoint);
	       printf("pup->b_endpoint: %s \n",pup->b_endpoint);
	  }
	  if ((tmp=(char*)calloc(MAX_LINE_LEN,sizeof(char)))==NULL) {
	       fprintf(stderr,"mod_inbounds: calloc() failed\n");
	       exit(-1);
	  }
	  
	  sprintf(tmp, "O %.6f UDP %s %s %i\n", 
		  dtime, pup->a_endpoint, pup->b_endpoint, status);
	  
	  if (fwrite(tmp, strlen(tmp), 1, stdout) <= 0) {
	       fprintf(stderr, "mod_inbounds: couldn't write to stdout\n");
	       exit(1);
	  }
	  fflush(stdout);
	  free(tmp);
	  conn->new = FALSE;
     }
     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds:udp_read() datalen is being calculated \n");
     
     /* Setting a pointer to the beginning of the TCP header */
#ifdef IP_IPVHL
     udp = (struct udphdr *) ((char *)pip + (4 * (pip->ip_vhl & 0x0f)));
#else
     udp = (struct udphdr *) ((char *)pip + (4 * pip->ip_hl));
#endif
     
   /* calculate the amount of user data */
     data_len = ntohs(pip->ip_len) - 
	  /* size of entire IP packet (and IP header) */
#ifdef IP_IPVHL
	  (4 * (pip->ip_vhl & 0x0f)) -        /* less the IP header */
#else
	  (4 * pip->ip_hl) -  /* less the IP header */
#endif
	  UDPHDR_LEN;
     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds: udp_read() datalen:%d \n",data_len);
     
     /* see in which direction this goes with */
     if (INBOUNDS_DEBUG) {
	  printf("INBOUNDS: %d \n",
		 pup->addr_pair.a_port);
	  printf("INBOUNDS: %d \n",
		 ntohs(udp->uh_sport));
     }

     // Do anything at all if only we captured the headers fully
     if(data_len >= 0) {
	  	  
	  if (pup->addr_pair.a_port == ntohs(udp->uh_sport))
	       dir = UDP_A2B;
	  else
	       dir = UDP_B2A;
	  
	  /*   if (data_len > 0) { // this packet has data in it 
	   * 
	   if(INBOUNDS_DEBUG)
	   printf("mod_inbounds:udp_read() this packet has data in it\n");
	   if (tv_lt(conn->first_data_time, conn->first_time)) {
	   conn->first_data_time = current_time;
	   conn->had_data = TRUE;
	   }
	   */    
	  delta=current_time;
	  tv_sub(&delta,conn->last_time);
	  conn->last_time = current_time;	  
	  if(dir == UDP_A2B) {// this is a question
	       // If what we had before was an answer, we can calculate AQIT
	       if(conn->dir==UDP_B2A) {
		    if(conn->a2qIdle.tv_sec==-1) {// First sample in the last
			                          // INBOUNDS_UPDATE_INTERVAL
			 conn->a2qIdle.tv_sec=0.0;
			 conn->a2qIdle.tv_usec=0.0;
			 tv_add(&conn->a2qIdle,delta);
		    }
		    else {
			 tv_add(&conn->a2qIdle,delta);
		    }
	       }
	       conn->dir = UDP_A2B;
	       conn->qNum++;
	       conn->qSum += data_len;
	  }
	  else {// this is an answer
	       // If what we had before was a question, we can calculate QAIT
	       Bool   done = FALSE;
	       if(conn->dir==UDP_A2B) {
		    if(conn->q2aIdle.tv_sec==-1) {// First sample in the last
			 // INBOUNDS_UPDATE_INTERVAL
			 conn->q2aIdle.tv_sec=0.0;
			 conn->q2aIdle.tv_usec=0.0;
			 tv_add(&conn->q2aIdle,delta);		  
		    }
		    else {
			 tv_add(&conn->q2aIdle,delta);
		    }
	       }
	       conn->dir = UDP_B2A;
	       conn->aNum++;
	       conn->aSum += data_len;
	  }
     } // END: if data_len >= 0
     
     /* Do the interactivity - it has to be done for both TCP and UDP */
     
     if ((elapsed(mod_info->last_udp_scheduled_time, current_time) / 1000000.0)
	 >= INBOUNDS_UDP_UPDATE_INTERVAL) {
	  AllUDPInteractivity();
     }

     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds:udp_read() exiting udp_read \n");
}


/* call the respective TCP and UDP routines to print the update messages */

static void
    AllTCPInteractivity(void)
{
     itcinfo *tcp_conn;
     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds: in AllTCPInteractivity() \n");
     
     for (tcp_conn = mod_info->tcp_conn_head; tcp_conn != NULL; 
	  tcp_conn = tcp_conn->next) {	
	  if (!tcp_conn->closed) {
	       TCPInteractivity(tcp_conn);
	  }
     }
     
     mod_info->last_tcp_scheduled_time.tv_sec += INBOUNDS_TCP_UPDATE_INTERVAL;
     mod_info->last_tcp_actual_time = current_time;

}

/* calculate and print out interactivity statistics for TCP connections */
static void
     TCPInteractivity(
			itcinfo *conn)
{
     char          *tmp;
     
     double	qAvg;
     double	aAvg;
     double	q2aIdle;
     double	a2qIdle;
     double        dtime;
     double        update_interval;
     timeval       first_time;
     
     if ((tmp=(char*)calloc(MAX_LINE_LEN,sizeof(char)))==NULL) {
	  fprintf(stderr,"itcptrace : calloc() failed\n");
	  exit(-1);
     }
     
     if (conn->had_data) {
	  first_time = conn->first_data_time;
     }
     else {
	  first_time = conn->first_time;
     }
     
     if (tv_lt(mod_info->last_tcp_actual_time, first_time)) {
	  update_interval = elapsed(conn->first_data_time, current_time) / 
	       1000000.0;
	  /* if this is the first packet belonging to the connection, 
	   we don't need to print statistics */
	  if (update_interval == 0) 
	       return;
     }
     else {
	  update_interval = elapsed(mod_info->last_tcp_actual_time, 
				    current_time) / 1000000.0;
     }
     if (update_interval < 1.0) {
	  update_interval = 1.0;
     }
     
     if (conn->qNum != 0) {
	  qAvg = conn->qSum / (double)conn->qNum;
     }
     else {
	  qAvg = 0;
     }
     if (conn->aNum != 0) {
	  aAvg = conn->aSum / (double)conn->aNum;
     }
     else {
	  aAvg = 0;
     }
     q2aIdle = (conn->q2aIdle.tv_sec + (conn->q2aIdle.tv_usec / 1000000.0)) / update_interval;
     a2qIdle = (conn->a2qIdle.tv_sec + (conn->a2qIdle.tv_usec / 1000000.0)) / update_interval ;
     
     dtime = current_time.tv_sec + (current_time.tv_usec / 1000000.0);
     
     sprintf(tmp, "U %.6f TCP %s %s %.3f %.3f %.3f %.6f %.6f\n",
	     dtime, conn->ptp->a_endpoint, conn->ptp->b_endpoint,
	     (conn->qNum / update_interval), qAvg, aAvg, q2aIdle, a2qIdle);
  
//     sprintf(tmp, "U TCP %.3f %.3f %.3f %.3f %.3f %.3f\n",
//	     conn->qSum, conn->qNum, qAvg, 
//	     conn->aSum, conn->aNum, aAvg);
     
     conn->qNum = 0;
     conn->aNum = 0;
     conn->qSum = 0;
     conn->aSum = 0;
     conn->q2aIdle.tv_sec = 0; conn->q2aIdle.tv_usec = 0;
     conn->a2qIdle.tv_sec = 0; conn->a2qIdle.tv_usec = 0;
     
     if (fwrite(tmp, strlen(tmp), 1, stdout) <= 0) {
	  fprintf(stderr, "mod_inbounds : couldn't write to stdout\n");
	  exit(1);
     }
     fflush(stdout);
     free(tmp);
     
}

static void 
     AllUDPInteractivity(void)
{
     iucinfo *udp_conn;
     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds: in AllUDPInteractivity() \n");

     if(do_udp) {
	  ClosedUDPConn();
	  for (udp_conn = mod_info->udp_conn_head; udp_conn != NULL; 
	       udp_conn = udp_conn->next) {
	       if (!udp_conn->closed) {  
		    UDPInteractivity(udp_conn);
	       }
	  }  
     } 
     
     mod_info->last_udp_scheduled_time.tv_sec += INBOUNDS_UDP_UPDATE_INTERVAL;
     mod_info->last_udp_actual_time = current_time;
     
}


/* calculate and print out UDP interactivity statistics */

static void
     UDPInteractivity(
		      iucinfo *conn)
{
     char *tmp;
     double       qAvg;
     double       aAvg;
     double       q2aIdle;
     double       a2qIdle;
     double        dtime;
     double        update_interval;
     //   timeval       first_time;
     // 
     if ((tmp=(char*)calloc(MAX_LINE_LEN,sizeof(char)))==NULL) {
	  fprintf(stderr,"itcptrace : calloc() failed\n");
	  exit(-1);
     }
     
     if(INBOUNDS_DEBUG)
	  printf("mod_inbounds:UDPDoInteractivity() \n");
     
     if (tv_lt(mod_info->last_udp_actual_time, conn->first_time)) {
	  update_interval = elapsed(conn->first_time, current_time) / 
	       1000000.0;
	  /* if this is the first packet belonging to the connection,
	   *        we don't need to print statistics */
	  if (update_interval == 0)
	       return;
     }
     else {
	  update_interval = 
	       elapsed(mod_info->last_udp_actual_time, current_time) / 1000000.0;
     }
     
     if (update_interval < 1.0) 
	  update_interval = 1.0;
     
     if (conn->qNum != 0) 
	  qAvg = conn->qSum / (double)conn->qNum;
     else 
	  qAvg = 0;
     
     if (conn->aNum != 0) 
	  aAvg = conn->aSum / (double)conn->aNum;
     else 
	  aAvg = 0;

     if(conn->q2aIdle.tv_sec == -1) {
	  // We could not calculate q2aIdle 
	  // in the last INBOUNDS_UDP_UPDATE_INTERVAL
	  // as there were no answers
	  q2aIdle=1.0;
     }
     else {			 
	  q2aIdle=(conn->q2aIdle.tv_sec + 
		   (conn->q2aIdle.tv_usec / 1000000.0)) /update_interval;
     }

     if(conn->a2qIdle.tv_sec == -1) {
	  // We could not calculate a2qIdle 
	  // in the last INBOUNDS_UDP_UPDATE_INTERVAL
	  // as there were no questions
	  a2qIdle=1.0;
     }
     else {			 
	  a2qIdle=(conn->a2qIdle.tv_sec + 
		   (conn->a2qIdle.tv_usec / 1000000.0)) /update_interval;
     }
     
     dtime = current_time.tv_sec + (current_time.tv_usec / 1000000.0);
     
     sprintf(tmp, "U %.6f UDP %s %s %.3f %.3f %.3f %.6f %.6f\n",
	     dtime, conn->pup->a_endpoint, conn->pup->b_endpoint,
	     (conn->qNum / update_interval), qAvg, aAvg, q2aIdle, a2qIdle);
     conn->qNum = 0;
     conn->aNum = 0;
     conn->qSum = 0;
     conn->aSum = 0;
     conn->q2aIdle.tv_sec = -1; conn->q2aIdle.tv_usec = 0;
     conn->a2qIdle.tv_sec = -1; conn->a2qIdle.tv_usec = 0;
     
     
     if (fwrite(tmp, strlen(tmp), 1, stdout) <= 0) {
	  fprintf(stderr, "mod_inbounds : couldn't write to stdout\n");
	  exit(1);
     }
     fflush(stdout);
     free(tmp);
}
   

/* look for timed out UDP connections */

static void
     ClosedUDPConn()
{
     iucinfo *udp_conn;
     
     for (udp_conn = mod_info->udp_conn_head; udp_conn != NULL; 
	  udp_conn = udp_conn->next) {
	  if (!udp_conn->closed) {
	       if((elapsed(udp_conn->last_time,current_time)/1000000.0) >= 
		  UDP_REMOVE_LIVE_CONN_INTERVAL) {
		    UDPInteractivity(udp_conn);
		    udp_conn->closed = TRUE;
		    PrintUDPCMsg(udp_conn);
	       }
	  }
     }
}

/* print the C messages for timed out UDP connections */

static void
     PrintUDPCMsg(iucinfo *udp_conn)
{
     char tmp[256];
     int status = 0;
     double dtime = 0;
     
     dtime = current_time.tv_sec + (current_time.tv_usec / 1000000.0);
     sprintf(tmp, "C %.6f UDP %s %s %i\n",
	     dtime, udp_conn->pup->a_endpoint, udp_conn->pup->b_endpoint, status);
#ifdef _DEBUG
     printf("%s", tmp);
#endif
     
     if (fwrite(tmp, strlen(tmp), 1, stdout) <= 0) {
	  fprintf(stderr, "mod_inbounds : couldn't write to stdout\n");
	  exit(1);
     }
     fflush(stdout);
     
}

void
     inbounds_nontcpudp_read(
			     struct ip *pip,
			     void *plast)
{
     struct protocol *last = NULL;
     struct protocol *current; 
     
     ++nontcpudp_packets;
#ifdef _MONITOR
     ipCheck(pip, plast);
#endif /* _MONITOR */
     
     if (plist == NULL) {
	  plist = (struct protocol *)MallocZ(sizeof(struct protocol));
	  current = plist;
	  current->count = 1;
	  current->next = NULL;
	  current->ip_p = pip->ip_p;
	  last = current;
     }
     else {
	  for (current = plist; current; current = current->next) {
	       if (current->ip_p == pip->ip_p) {
		    current->count++;
		    break;
	       }
	       else {
		    last = current;
	       }
	  }
	  if (current == NULL) { /* protocol is not on our list yet */
	       current = (struct protocol *)MallocZ(sizeof(struct protocol));
	       current->ip_p = pip->ip_p;
	       current->count = 1;
	       current->next = NULL;
	       last->next = current;
	       last = current;
	  }
     }
}



/* Data is considered a NEW burst if:
 *  1) All previous data was ACKed
 *  2) There was intervening data in the other direction
 *  3) idletime > RTT -- ???
 */
static Bool
     IsNewBurst(
		itcinfo *conn,
		tcb *ptcb,
		struct tcphdr *tcp,
		Bool dir)
{
     
     seqnum seq = ntohl(tcp->th_seq);
     tcb *orig_lastdata;
     
     tcb *ptcb_otherdir = ptcb->ptwin; 
     
     /* remember the last direction the data flowed */
     orig_lastdata = conn->tcb_lastdata;
     conn->tcb_lastdata = ptcb;
     
     /* it's only a NEW burst if there was a PREVIOUS burst */
     if (conn->burst_bytes == 0) {
	  if (0)
	       printf("%s <-> %s: same dir (no previous)\n", ptcb->ptp->a_endpoint, ptcb->ptp->b_endpoint);
	  return(FALSE);
     }
     
     /* check for old data ACKed */
     /*
      if (SEQ_LESSTHAN(ptcb_otherdir->ack,seq)) {
      if (0) //(debug > 2) 
      printf("%s <-> %s: same dir (no acks)\n", ptcb->ptp->a_endpoint, ptcb->ptp->b_endpoint);
      return(FALSE);
      }*/
     
     /* check for idletime > RTT */
     /*    {
      u_long etime_usecs = elapsed(conn->last_data_time, current_time);
      u_long last_rtt_usecs = ptcb->rtt_last;
      if ((last_rtt_usecs != 0) && (etime_usecs < last_rtt_usecs)) {
      if (debug > 2) 
      printf("(idletime) ");
      return(FALSE);
      }
      }
      */
     /* check for intervening data */
     if (ptcb == orig_lastdata) {
	  /* no intervening data */
	  if (0)
	       printf("%s <-> %s: same dir\n", ptcb->ptp->a_endpoint, 
		      ptcb->ptp->b_endpoint);
	  return(FALSE);
     }
     
     if (debug) {
	  if (dir == conn->dir) {
	       fprintf(stderr, 
		       "WARNING for conn %s<->%s, my dir=%i, packet's dir=%i\n", 
		       ptcb->ptp->a_endpoint, ptcb->ptp->b_endpoint, conn->dir, dir);
	  }
     }
     if (0) 
	  printf("%s <-> %s: diff dir\n", ptcb->ptp->a_endpoint, 
		 ptcb->ptp->b_endpoint);
     return(TRUE);
}

static void
ipCheck(
	struct ip *pip,
	void *plast)
{
     /* make sure we have enough of the packet */
     if ((unsigned)pip+sizeof(struct ip)-1 > (unsigned)plast) {
	  fprintf(stderr, "INBOUNDS: packet too short for IP details\n");
	  return;
     }
     
     if (!ip_cksum_valid(pip,plast)) {
	  fprintf(stderr, "INBOUNDS: packet %lu: bad IP checksum\n", pnum);
     }
     
     /* check that IP addresses are different */
     if (pip->ip_src.s_addr == pip->ip_dst.s_addr) {
	  fprintf(stderr, 
		  "INBOUNDS: packet %lu same source and dest IP addresses %s\n",
		  pnum, inet_ntoa(pip->ip_src));
     }
     /* check that the packet doesn't have private addresses */
     /* class A addresses */
     if (((unsigned int)(pip->ip_src.s_addr >> 24) == 10) ||
	 ((unsigned int)(pip->ip_dst.s_addr >> 24) == 10) ||
	 /* class B addresses */
	 (((unsigned int)(pip->ip_src.s_addr >> 24) == 172) &&
	  ((((unsigned int)(pip->ip_src.s_addr >> 16) & 0xff) >= 16) &&
	   (((unsigned int)(pip->ip_src.s_addr >> 16) & 0xff) < 32))) || 
	 (((unsigned int)(pip->ip_dst.s_addr >> 24) == 172) &&
	  ((((unsigned int)(pip->ip_dst.s_addr >> 16) & 0xff) >= 16) &&
	   ((((unsigned int)(pip->ip_dst.s_addr >> 16) & 0xff) < 32)))) ||
	 /* class C addresses */ 
	 (((unsigned int)(pip->ip_src.s_addr >> 24) == 192) &&
	  (((unsigned int)(pip->ip_src.s_addr >> 16) & 0xff) == 168)) ||
	 (((unsigned int)(pip->ip_dst.s_addr >> 24) == 192) &&
	  (((unsigned int)(pip->ip_dst.s_addr >> 16) & 0xff) == 168))) {
	  fprintf(stderr, "INBOUNDS: packet %lu private address %s", 
		  pnum, inet_ntoa(pip->ip_src)); 
	  fprintf(stderr, " -> %s\n", inet_ntoa(pip->ip_dst));
     }
     /* check that addresses don't violate standards */
     if (((unsigned int)(pip->ip_dst.s_addr >> 24) == 0) ||
	 ((unsigned int)(pip->ip_src.s_addr >> 24) == 255) ||
	 ((unsigned int)(pip->ip_src.s_addr >> 24) == 127) ||
	 ((unsigned int)(pip->ip_dst.s_addr >> 24) == 127)) {
	  fprintf(stderr, "INBOUNDS: packet %lu standard violation %s",
		  pnum, inet_ntoa(pip->ip_src));
	  fprintf(stderr, " -> %s\n", inet_ntoa(pip->ip_dst));
     }
     
     /* check whether TTL is low */
     /* won't do for a while */
     /*
      if ((unsigned int)pip->ip_ttl < 10) {
      fprintf(stderr, "INBOUNDS: low TTL(%u) for %s -> ",
      (unsigned int)pip->ip_ttl, inet_ntoa(pip->ip_src));
      fprintf(stderr, "%s\n",  inet_ntoa(pip->ip_dst)); 
      }
      */
     
     /* check whether do-not-fragment bit is set */
     /* no, too many packets *
      if (pip->ip_off & IP_DF) {
      fprintf(stderr, "INBOUNDS: DF bit set for %s", inet_ntoa(pip->ip_src));
      fprintf(stderr, "-> %s, size %i bytes\n", 
      inet_ntoa(pip->ip_dst), pip->ip_len);
      } 
      */
     /* check options: packet is not strict source routed */
#ifdef IP_IPVHL
     if ((pip->ip_vhl & 0x0f) != 5) {
#else
     if (pip->ip_hl != 5) {
#endif
	  char *popt = (char *)pip + 20;
	  void *plast_option;
	  
	  /* find the last option in the file */
#ifdef IP_IPVHL
	  plast_option = (char *)pip+4*(pip->ip_vhl & 0x0f)-1;
#else
	  plast_option = (char *)pip+4*pip->ip_hl-1;
#endif
	  if (plast_option > plast)
	       plast_option = plast; /* truncated shorter than that */
	  
	  while ((void *)popt <= plast_option) {
	       u_int opt = *popt;
	       u_int len = *(popt+1);
	       
	       /* check for truncated option */
	       if ((void *)(popt+len-1) > plast) {
		    fprintf(stderr, "INBOUNDS: packet %lu IP option (truncated) in %s",
			    pnum, inet_ntoa(pip->ip_src)); 
		    fprintf(stderr, " -> %s\n", inet_ntoa(pip->ip_dst));
		    continue;
	       }
	       
	       if (opt == 9) {
		    fprintf(stderr, "INBOUNDS: packet %lu strict source route: %s",
			    pnum, inet_ntoa(pip->ip_src)); 
		    fprintf(stderr, " -> %s\n", inet_ntoa(pip->ip_dst));
	       }
	       if (opt == 3) {
		    fprintf(stderr, "INBOUNDS: packet %lu loose source route: %s",
			    pnum, inet_ntoa(pip->ip_src)); 
		    fprintf(stderr, " -> %s\n", inet_ntoa(pip->ip_dst));
	       }
	       if (len <= 0)
		    break;
	       popt += len;
	  }
     }
     
}

static void 
tcpCheck(
 	 struct ip *pip, 
	 tcp_pair *ptp,
	 void *plast)
{
  struct tcphdr *ptcp;
  int dir;
  Bool valid = TRUE;

#ifdef IP_IPVHL
  if (((unsigned int)pip->ip_len - (unsigned int)(pip->ip_vhl & 0x0f)) <
#else
  if (((unsigned int)pip->ip_len - (unsigned int)pip->ip_hl) <
#endif
      (unsigned int)sizeof(struct tcphdr)) {
    fprintf(stderr, "INBOUNDS: packet %lu TCP packet too short for TCP header %s",
	    pnum, inet_ntoa(pip->ip_src));
    fprintf(stderr, " -> %s\n", inet_ntoa(pip->ip_dst));
  }

  /* check flags */
  /* 1) SYN and FIN set */
  /* 2) SYN and RST set */
  /* 3) SYN and URG set */
  /* 4) none set  - deprecated */

  /* Setting a pointer to the beginning of the TCP header */
#ifdef IP_IPVHL
  ptcp = (struct tcphdr *) ((char *)pip + (4 * (pip->ip_vhl & 0x0f)));
#else
  ptcp = (struct tcphdr *) ((char *)pip + (4 * pip->ip_hl));
#endif

  /* verify checksum */
  if (!tcp_cksum_valid(pip,ptcp,plast)) {
    fprintf(stderr, "INBOUNDS: packet %lu invalid TCP checksum\n", pnum);
  }
   
  /* check port numbers */
  /* 1) not the same - now deprecated  */
  /* 2) not zero        */
   /*
  if (ptp->addr_pair.a_port == ptp->addr_pair.b_port) {
    fprintf(stderr, "INBOUNDS: same port numbers %s -> %s\n",
	    ptp->a_endpoint, ptp->b_endpoint);
  }
    */
   if ((ptp->addr_pair.a_port == 0) || (ptp->addr_pair.b_port == 0)) {
      fprintf(stderr, "INBOUNDS: packet %lu zero port number(s) %s -> %s\n",
	      pnum, ptp->a_endpoint, ptp->b_endpoint);
   }

  /* see which of the 2 TCB's this goes with */
  if (ptp->addr_pair.a_port == ntohs(ptcp->th_sport)) {
    dir = A2B;
  } else {
    dir = B2A;
  }

  if (SYN_SET(ptcp)) {
    if (FIN_SET(ptcp)) {
      fprintf(stderr, "INBOUNDS: packet %lu invalid TCP flags: SYN FIN ", pnum);
      valid = FALSE;
    }
    if (RESET_SET(ptcp)) {
      if (valid) {
        fprintf(stderr, "INBOUNDS: packet %lu invalid TCP flags: SYN RST ", pnum);
        valid = FALSE;
      }
      else {
        fprintf(stderr, "RST ");
      }
    }
    if (URGENT_SET(ptcp)) {
      if (valid) {
        fprintf(stderr, "INBOUNDS: packet %lu invalid TCP flags: SYN URG ", pnum);
        valid = FALSE;
      }
      else {
        fprintf(stderr, "URG ");
      }
    }
    if (PUSH_SET(ptcp)) {
      if (valid) {
        fprintf(stderr, "INBOUNDS: packet %lu invalid TCP flags: SYN PSH ", pnum);
        valid = FALSE;
      }
      else {
        fprintf(stderr, "PSH ");
      }
    }
    if (!valid) {
      fprintf(stderr, "set in ");
      if (dir == A2B) 
       fprintf(stderr, "%s -> %s\n", ptp->a_endpoint, ptp->b_endpoint);
      else
       fprintf(stderr, "%s -> %s\n", ptp->b_endpoint, ptp->a_endpoint);
      if (ptp->packets <= 1) {
	fprintf(stderr, "packet %lu doesn't belong to a conn", pnum);
      }
      else {
	fprintf(stderr, "packet %lu belongs to a conn with %llu packets\n",
		pnum, ptp->packets);
      }
    }
  }
  else {
     if (RESET_SET(ptcp) && FIN_SET(ptcp)) {
	fprintf(stderr, 
		"INBOUNDS: packet %lu invalid TCP flags: RST FIN set in %s -> %s\n",
		pnum, (dir == A2B) ? ptp->a_endpoint : ptp->b_endpoint,
		(dir == A2B) ? ptp->b_endpoint : ptp->a_endpoint);
      if (ptp->packets <= 1) {
	fprintf(stderr, "packet %lu doesn't belong to a conn", pnum);
      }
      else {
	fprintf(stderr, "packet belongs to a conn with %llu packets\n",
		pnum, ptp->packets);
      }
     }
  }

#ifdef TCP_THXOFF
  if ((ptcp->th_xoff & 0x0f) != 0) {
    fprintf(stderr,
	    "INBOUNDS: packet %lu 4 TCP reserved bits are not zero (0x%01x)\n",
	    pnum, (ptcp->th_xoff & 0x0f));
  }
#else
  if (ptcp->th_x2 != 0) {
    fprintf(stderr,
	    "INBOUNDS: packet %lu 4 TCP reserved bits are not zero (0x%01x)\n",
	    pnum, ptcp->th_x2);
  }
#endif
  if ((ptcp->th_flags & 0xc0) != 0) {
    fprintf(stderr,
	    "INBOUNDS: packet %lu upper TCP flag bits are not zero (0x%02x)\n",
	    pnum, ptcp->th_flags);
  }
  
}

static void 
udpCheck(
	 struct ip *pip, 
	 udp_pair *pup, 
	 void *plast)
{
   struct udphdr *pudp;
   int ret;
   
   /* look for a UDP header */
   ret = getudp(pip, &pudp, &plast);
   if (ret <= 0) {
      if (!udp_cksum_valid(pip,pudp,plast)) {
	 fprintf(stderr, "INBOUNDS: packet %lu invalid UDP checksum\n", pnum);
      }
   }
}

#endif /* LOAD_MODULE_INBOUNDS */


