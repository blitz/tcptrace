/*
 * Copyright (c) 1994, 1995, 1996, 1997
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
static char const rcsid_http[] =
   "$Id$";

#include "tcptrace.h"
#include <sys/mman.h>


#define DEFAULT_SERVER_PORT 80

/* info gathered for each GET */
struct get_info {
    timeval get_time;		/* when CLIENT sent GET */
    timeval send_time;		/* when SERVER sent CONTENT */
    timeval ack_time;		/* when CLIENT acked CONTENT */
    unsigned content_length;	/* as reported by server */
    char *get_string;		/* content of GET string */

    struct get_info *next;
};



/* linked list of times */
struct time_stamp {
    timeval 	       thetime;
    u_long 	       position;
    struct time_stamp *next;
    struct time_stamp *prev;
};


/* info kept for each connection */
static struct http_info {
    timeval c_syn_time;		/* when CLIENT sent SYN */
    timeval s_syn_time;		/* when SERVER sent SYN */
    timeval c_fin_time;		/* when CLIENT sent FIN */
    timeval s_fin_time;		/* when SERVER sent FIN */

    /* info about the TCP connection */
    tcp_pair *ptp;
    tcb *tcb_client;
    tcb *tcb_server;

    /* when querries (GETs) were sent by client */
    struct time_stamp get_head;
    struct time_stamp get_tail;


    /* when answers (CONTENT) were sent by server */
    struct time_stamp data_head;
    struct time_stamp data_tail;

    /* when answers (CONTENT) were acked by client */
    struct time_stamp ack_head;
    struct time_stamp ack_tail;

    /* linked list of requests */
    struct get_info *gets_head;
    struct get_info *gets_tail;

    struct http_info *next;
    struct http_info *prev;
} *httphead = NULL, *httptail = NULL;



/* which port are we monitoring?? */
static unsigned httpd_port;


/* local routines */
static timeval WhenSent(struct time_stamp *phead, struct time_stamp *ptail,
			u_long position);
static timeval WhenAcked(struct time_stamp *phead, struct time_stamp *ptail,
			 u_long position);
static void MFMap(MFILE *mf, char **firstbyte, char **lastbyte);
static void FindGets(struct http_info *ph);
static void FindContent(struct http_info *ph);
static void HttpGather(struct http_info *ph);
static struct http_info *MakeHttpRec(void);
static struct get_info *MakeGetRec(struct http_info *ph);
static u_long DataOffset(tcb *tcb, seqnum seq);
static void AddGetTS(struct http_info *ph, u_long position);
static void AddDataTS(struct http_info *ph, u_long position);
static void AddAckTS(struct http_info *ph, u_long position);
static void AddTS(struct time_stamp *phead, struct time_stamp *ptail,
		  u_long position);
static double ts2d(timeval *pt);
static void HttpPrintone(MFILE *pmf, struct http_info *ph);
static void HttpDoPlot();
static struct http_info *FindPH(tcp_pair *ptp, struct tcphdr *ptcp);


/* useful macros */
#define IS_CLIENT(ptcp) ((ptcp)->th_dport == httpd_port)
#define IS_SERVER(ptcp) ((ptcp)->th_dport != httpd_port)


/* Mostly as a module example, here's a plug in that records HTTP info */
int
http_init(
    int argc,
    char *argv[])
{
    int i;
    int enable=0;

    for (i=0; i < argc; ++i) {
	if (strncmp(argv[i],"-H",2) == 0) {
	    /* I want to be called */
	    enable = 1;
	    if (isdigit(argv[i][2])) {
		httpd_port = atoi(argv[i]+2);
	    } else {
		httpd_port = DEFAULT_SERVER_PORT;
	    }
	    printf("Capturing HTTP traffic (port %d)\n", httpd_port);
	    argv[i] = NULL;
	}
    }

    if (!enable)
	return(0);	/* don't call me again */


    /* init stuff */

    /* We need to save the contents for accurate reconstruction of questions */
    /* and answers */
    save_tcp_data = TRUE;


    return(1);	/* TRUE means call http_read and http_done later */
}


/* N.B.  first byte is position _1_ */
static u_long
DataOffset(
    tcb *tcb,
    seqnum seq)
{
    u_long off;
    
    /* we're going to be a little lazy and assume that a http connection */
    /* can't be longer than 2**32  */
    if (seq > tcb->syn)
	off = seq-tcb->syn;
    else
	off = tcb->syn-seq;

    if (debug)
	fprintf(stderr,"DataOffset: seq is %ld, syn is %ld, offset is %ld\n",
		seq, tcb->syn, off);

    return(off);
}


static struct get_info *
MakeGetRec(
    struct http_info *ph)
{
    struct get_info *pg;

    pg = MallocZ(sizeof(struct get_info));

    /* put at the end of the chain */
    if (ph->gets_head == NULL) {
	ph->gets_head = pg;
	ph->gets_tail = pg;
    } else {
	ph->gets_tail->next = pg;
	ph->gets_tail = pg;
    }

    return(pg);
}


static struct http_info *
MakeHttpRec()
{
    struct http_info *ph;

    ph = MallocZ(sizeof(struct http_info));

    ph->get_head.next = &ph->get_tail;
    ph->get_tail.prev = &ph->get_head;
    ph->get_tail.position = 0xffffffff;

    ph->data_head.next = &ph->data_tail;
    ph->data_tail.prev = &ph->data_head;
    ph->data_tail.position = 0xffffffff;

    ph->ack_head.next = &ph->ack_tail;
    ph->ack_tail.prev = &ph->ack_head;
    ph->ack_tail.position = 0xffffffff;

    /* put it at the tail of the list */
    if (httphead == NULL) {
	httptail = ph;
	httphead = ph;
    } else {
	ph->prev = httptail;
	httptail->next = ph;
	httptail = ph;
    }

    return(ph);
}


static void
AddGetTS(
    struct http_info *ph,
    u_long position)
{
    AddTS(&ph->get_head,&ph->get_tail,position);
}



static void
AddDataTS(
    struct http_info *ph,
    u_long position)
{
    AddTS(&ph->data_head,&ph->data_tail,position);
}


static void
AddAckTS(
    struct http_info *ph,
    u_long position)
{
    AddTS(&ph->ack_head,&ph->ack_tail,position);
}


/* add a timestamp to the record */
/* HEAD points to the smallest position numbers */
/* TAIL points to the largest position numbers */
static void
AddTS(
    struct time_stamp *phead,
    struct time_stamp *ptail,
    u_long position)
{
    struct time_stamp *pts;
    struct time_stamp *pts_new;

    pts_new = MallocZ(sizeof(struct time_stamp));
    pts_new->thetime = current_time;
    pts_new->position = position;

    for (pts = ptail->prev; pts != NULL; pts = pts->prev) {
	if (position == pts->position)
	    return; /* ignore duplicates */

	if (position > pts->position) {
	    /* it goes AFTER this one (pts) */
	    pts_new->next = pts->next;
	    pts_new->prev = pts;
	    pts->next = pts_new;
	    pts_new->next->prev = pts_new;
	    return;
	}
    }

    /* can't fail, the tail has timestamp 0 */
}

static struct http_info *
FindPH(
    tcp_pair *ptp,
    struct tcphdr *ptcp)
{
    struct http_info *ph;

    /* find the record for this packet */
    for (ph=httphead; ph; ph=ph->next) {
	if (ph->ptp == ptp)
	    break;
    }

    if (!ph) {
	/* didn't find it, make one up */
	ph = MakeHttpRec();
	ph->ptp = ptp;

	/* determine the server and client tcb's */
	if (ptp->addr_pair.a_port == httpd_port) {
	    ph->tcb_client = &ptp->b2a;
	    ph->tcb_server = &ptp->a2b;
	} else {
	    ph->tcb_client = &ptp->a2b;
	    ph->tcb_server = &ptp->b2a;
	}
    }

    return(ph);
}



void
http_read(
    struct ip *pip,	/* the packet */
    tcp_pair *ptp,	/* info I have about this connection */
    void *plast)	/* past byte in the packet */
{
    struct http_info *ph;
    struct tcphdr *ptcp;
    unsigned tcp_length;
    unsigned tcp_data_length;
    char *pdata;

    /* find the start of the TCP header */
    ptcp = (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);
    tcp_length = pip->ip_len - (4 * pip->ip_hl);
    tcp_data_length = tcp_length - (4 * ptcp->th_off);

    /* verify port */
    if ((ptcp->th_sport != httpd_port) && (ptcp->th_dport != httpd_port))
	return;

    /* find the record for this packet */
    ph = FindPH(ptp,ptcp);

    /* find the data */
    pdata = (char *)ptcp + (unsigned)ptcp->th_off*4;

    /* for client, record both ACKs and DATA time stamps */
    if (IS_CLIENT(ptcp)) {
	if (tcp_data_length > 0) {
	    AddGetTS(ph,DataOffset(ph->tcb_client,ptcp->th_seq));
	}
	if (ACK_SET(ptcp)) {
	    AddAckTS(ph,DataOffset(ph->tcb_server,ptcp->th_ack));
	}
    }

    /* for server, record DATA time stamps */
    if (IS_SERVER(ptcp)) {
	if (tcp_data_length > 0) {
	    AddDataTS(ph,DataOffset(ph->tcb_server,ptcp->th_seq));
	}
    }

    
    /* we also want the time that the FINs were sent */
    if (FIN_SET(ptcp)) {
	if (IS_SERVER(ptcp)) {
	    /* server */
	    if (ZERO_TIME(&(ph->s_fin_time)))
		ph->s_fin_time = current_time;
	} else {
	    /* client */
	    if (ZERO_TIME(&ph->c_fin_time))
		ph->c_fin_time = current_time;
	}
    }

    /* we also want the time that the SYNs were sent */
    if (SYN_SET(ptcp)) {
	if (IS_SERVER(ptcp)) {
	    /* server */
	    if (ZERO_TIME(&ph->s_syn_time))
		ph->s_syn_time = current_time;
	} else {
	    /* client */
	    if (ZERO_TIME(&ph->c_syn_time))
		ph->c_syn_time = current_time;
	}
    }
}


static double
ts2d(timeval *pt)
{
    double d;
    d = pt->tv_sec;
    d += (double)pt->tv_usec/1000000;
    return(d);
}


static void
MFMap(
    MFILE *mf,
    char **firstbyte,
    char **lastbyte)
{
    int fd;
    char *vaddr;
    int len;
    
    /* find length of file */
    if (Mfseek(mf,0,SEEK_END) != 0) {
	perror("fseek");
	exit(-1);
    }
    len = Mftell(mf);

    /* Memory map the entire file */
    fd = Mfileno(mf);
    vaddr = mmap((caddr_t) 0,	/* put it anywhere	*/
		 len,		/* fixed size		*/
		 PROT_READ,	/* read only		*/
		 MAP_PRIVATE,	/* won't be sharing...	*/
		 fd,		/* attach to 'fd'	*/
		 (off_t) 0);	/* ... offset 0 in 'fd'	*/
    if (vaddr == MAP_FAILED) {
	perror("mmap");
	exit(-1);
    }

    *firstbyte = vaddr;
    *lastbyte = vaddr+len-1;

    return;
}


static void
HttpGather(
    struct http_info *ph)
{
    while (ph) {
	FindGets(ph);
	FindContent(ph);

	ph = ph->next;
    }
}


#ifdef OLD
static void
PrintTSChain(
    struct time_stamp *phead,
    struct time_stamp *ptail)
{
    struct time_stamp *pts;

    for (pts = phead->next; pts != ptail; pts = pts->next) {
	printf("Pos: %ld  time: %s\n",
	       pts->position, ts2ascii(&pts->thetime));
    }
}
#endif


/* when was the byte at offset "position" acked?? */
/* return the timeval for the record of the smallest position >= "position" */
static timeval
WhenAcked(
    struct time_stamp *phead,
    struct time_stamp *ptail,
    u_long position)
{
    struct time_stamp *pts;
    timeval epoch = {0,0};

/*     printf("pos:%ld, Chain:\n", position); */
/*     PrintTSChain(phead,ptail); */

    for (pts = phead->next; pts != NULL; pts = pts->next) {
/* 	fprintf(stderr,"Checking pos %ld against %ld\n", */
/* 		position, pts->position); */
	if (pts->position >= position) {
	    /* sent after this one */
	    return(pts->thetime);
	}
    }

    /* fails if we can't find it */
    return(epoch);
}



/* when was the byte at offset "position" sent?? */
/* return the timeval for the record of the largest position <= "position" */
static timeval
WhenSent(
    struct time_stamp *phead,
    struct time_stamp *ptail,
    u_long position)
{
    struct time_stamp *pts;
    timeval epoch = {0,0};

/*     printf("pos:%ld, Chain:\n", position); */
/*     PrintTSChain(phead,ptail); */

    for (pts = ptail->prev; pts != phead; pts = pts->prev) {
/* 	fprintf(stderr,"Checking pos %ld against %ld\n", */
/* 		position, pts->position); */
	if (pts->position <= position) {
	    /* sent after this one */
	    return(pts->thetime);
	}
    }

    /* fails if we can't find it */
    return(epoch);
}




static void
FindContent(
    struct http_info *ph)
{
    tcb *tcb = ph->tcb_server;
    MFILE *mf = tcb->extracted_contents_file;
    char *pdata;
    char *plast;
    char *pch;
    struct get_info *pget;
    u_long position;

    /* Memory map the entire file (I hope it's short!) */
    MFMap(mf,&pdata,&plast);

    /* search for Content-Length */
    pget = ph->gets_head;
    for (pch = pdata; pch <= (char *)plast; ++pch) {
	if (strncasecmp(pch,"Content-Length:", 15) == 0) {
	    /* find the value */
	    pget->content_length = atoi(&pch[16]);

	    /* remember where it started */
	    position = pch - pdata + 1;

	    /* grab the time stamps */
	    pget->send_time = WhenSent(&ph->data_head,&ph->data_tail,position);
	    pget->ack_time = WhenAcked(&ph->ack_head,&ph->ack_tail,position);

	    /* skip to the next request */
	    pget = pget->next;

	    if (!pget) {
		/* no more questions, quit */
		return;
	    }
	}
    }
}



static void
FindGets(
    struct http_info *ph)
{
    tcb *tcb = ph->tcb_client;
    MFILE *mf = tcb->extracted_contents_file;
    char *pdata;
    char *plast;
    char *pch;
    char *pch2;
    struct get_info *pget;
    char getbuf[256];
    u_long position;
    int j;

    /* Memory map the entire file (I hope it's short!) */
    MFMap(mf,&pdata,&plast);

    /* search for GET */
    for (pch = pdata; pch <= (char *)plast; ++pch) {
	if (strncasecmp(pch,"get ", 4) == 0) {
	    /* make a new record for this entry */
	    pget = MakeGetRec(ph);

	    /* remember where it started */
	    position = pch - pdata + 1;

	    /* grab the GET string */
	    for (j=0,pch2 = pch+4; ; ++j,++pch2) {
		if ((*pch2 == '\n') || (*pch2 == '\r') || (j >= sizeof(getbuf))) {
		    getbuf[j] = '\00';
		    pch = pch2;  /* skip forward */
		    break;
		}
		getbuf[j] = *pch2;
	    }
	    pget->get_string = strdup(getbuf);

	    /* grab the time stamps */
	    pget->get_time = WhenSent(&ph->get_head,&ph->get_tail,position);
	}
    }
}


#define NCOLORS 8
char *ColorNames[NCOLORS] =
{"green", "red", "blue", "yellow", "purple", "orange", "magenta", "pink" };


static void
HttpDoPlot()
{
    PLOTTER p = NO_PLOTTER;
    struct http_info *ph;
    struct get_info *pget;
    int y_axis = 1000;
    int ix_color = 0;
    char buf[100];
    struct time_stamp *pts;

    for (ph=httphead; ph; ph=ph->next) {
	tcp_pair *ptp = ph->ptp;
	tcb a2b, b2a;

	if (ptp == NULL)
	    continue;

	a2b = ptp->a2b;
	b2a = ptp->b2a;

	ix_color = (ix_color + 1) % NCOLORS;

	if (p==NO_PLOTTER)
	    p = new_plotter(&ptp->a2b,"HTTP","time","URL","_http.xpl");

	y_axis += 2;

	/* plot the TCP connection lifetime */
	plotter_perm_color(p,ColorNames[ix_color]);
	plotter_larrow(p, ph->ptp->first_time, y_axis);
	plotter_rarrow(p, ph->ptp->last_time, y_axis);
	plotter_line(p,
		     ph->ptp->first_time, y_axis,
		     ph->ptp->last_time, y_axis);

	/* label the connection */
	plotter_text(p,ph->ptp->first_time,y_axis,"b",
		     (sprintf(buf,"%s ==> %s",
			      ph->ptp->a_endpoint, ph->ptp->b_endpoint), buf));

	/* mark the data packets */
	for (pts=ph->data_head.next; pts->next; pts=pts->next) {
	    plotter_tick(p,pts->thetime,y_axis,'d');
	}
		     

	/* plot the SYN's */
	if (!ZERO_TIME(&ph->c_syn_time)) {
	    plotter_tick(p,ph->c_syn_time,y_axis,'u');
	    plotter_text(p,ph->c_syn_time,y_axis,"a","Clnt SYN");
	}
	if (!ZERO_TIME(&ph->s_syn_time)) {
	    plotter_tick(p,ph->s_syn_time,y_axis,'u');
	    plotter_text(p,ph->s_syn_time,y_axis,"a","Serv Syn");
	}

	/* plot the FINs */
	if (!ZERO_TIME(&ph->c_fin_time)) {
	    plotter_tick(p,ph->c_fin_time,y_axis,'u');
	    plotter_text(p,ph->c_fin_time,y_axis,"a","Clnt Fin");
	}
	if (!ZERO_TIME(&ph->s_fin_time)) {
	    plotter_tick(p,ph->s_fin_time,y_axis,'u');
	    plotter_text(p,ph->s_fin_time,y_axis,"a","Serv Fin");
	}

	y_axis += 4;

	for (pget = ph->gets_head; pget; pget = pget->next) {

	    if ((pget->send_time.tv_sec == 0) ||
		(pget->get_time.tv_sec == 0) ||
		(pget->ack_time.tv_sec == 0))
		continue;
	    
	    plotter_temp_color(p,"white");
	    plotter_text(p, pget->get_time, y_axis, "l", pget->get_string);

	    plotter_diamond(p, pget->get_time, y_axis);
	    plotter_larrow(p, pget->send_time, y_axis);
	    plotter_rarrow(p, pget->ack_time, y_axis);
	    plotter_line(p,
			 pget->send_time, y_axis,
			 pget->ack_time, y_axis);
	    plotter_temp_color(p,"white");
	    plotter_text(p, pget->ack_time, y_axis, "r",
			 (sprintf(buf,"%d",pget->content_length),buf));


	    y_axis += 2;

	}


    }
}


static void
HttpPrintone(
    MFILE *pmf,
    struct http_info *ph)
{
    tcp_pair *ptp = ph->ptp;
    tcb *pab = &ptp->a2b;
    tcb *pba = &ptp->b2a;
    struct get_info *pget;
    u_long missing;
    double etime;

    if (!ptp)
	return;
	
    printf("%s ==> %s (%s2%s)\n",
	   ptp->a_endpoint, ptp->b_endpoint,
	   ptp->a2b.host_letter, ptp->b2a.host_letter);

    /* see if we got all the bytes */
    missing = pab->trunc_bytes + pba->trunc_bytes;
    missing += pab->fin-pab->syn-1-(pab->data_bytes-pab->rexmit_bytes);
    missing += pba->fin-pba->syn-1-(pba->data_bytes-pba->rexmit_bytes);
    if (missing != 0)
	printf("WARNING!!!!  Information may be invalid, %ld bytes were not captured\n",
	       missing);

    printf("  Server Syn Time:      %s (%.3f)\n",
	   ts2ascii(&ph->s_syn_time),
	   ts2d(&ph->s_syn_time));
    printf("  Client Syn Time:      %s (%.3f)\n",
	   ts2ascii(&ph->c_syn_time),
	   ts2d(&ph->c_syn_time));
    printf("  Server Fin Time:      %s (%.3f)\n",
	   ts2ascii(&ph->s_fin_time),
	   ts2d(&ph->s_fin_time));
    printf("  Client Fin Time:      %s (%.3f)\n",
	   ts2ascii(&ph->c_fin_time),
	   ts2d(&ph->c_fin_time));

    for (pget = ph->gets_head; pget; pget = pget->next) {
	printf("    Request for '%s'\n", pget->get_string);
	printf("\tContent Length:      %d\n", pget->content_length);
	printf("\tTime GET sent:       %s (%.3f)\n",
	       ts2ascii(&pget->get_time), ts2d(&pget->get_time));
	printf("\tTime Answer started: %s (%.3f)\n",
	       ts2ascii(&pget->send_time), ts2d(&pget->send_time));
	printf("\tTime Answer ACKed:   %s (%.3f)\n",
	       ts2ascii(&pget->ack_time), ts2d(&pget->ack_time));

	/* elapsed time, GET started to answer started */
	etime = elapsed(pget->get_time,pget->send_time);
	etime /= 1000;  /* us to msecs */
	printf("\tElapsed time:  %.0f ms (GET to first byte sent)\n", etime);

	/* elapsed time, GET started to answer ACKed */
	etime = elapsed(pget->get_time,pget->ack_time);
	etime /= 1000;  /* us to msecs */
	printf("\tElapsed time:  %.0f ms (GET to content ACKed)\n", etime);
    }

#ifdef OLD
    Mfprintf(pmf,"%.3f %.3f %.3f %.3f %d %s\n",
	     ts2d(&ph->syn_time),
	     ts2d(&ph->get_time),
	     ts2d(&ph->lastack_time),
	     ts2d(&ph->fin_time),
	     ph->content_length,
	     ph->path);
#endif
}



void
http_done(void)
{
    MFILE *pmf;
    struct http_info *ph;

    /* just return if we didn't grab anything */
    if (!httphead)
	return;

    /* gather up the information */
    HttpGather(httphead);

    pmf = Mfopen("http.times","w");

    printf("Http module output:\n");

    for (ph=httphead; ph; ph=ph->next) {
	HttpPrintone(pmf,ph);
    }

    HttpDoPlot();

    Mfclose(pmf);
}


void
http_usage(void)
{
    printf("\t\t-H[P]\tprint info about http traffic (on port P, default %d)\n",
	   DEFAULT_SERVER_PORT);
}


#ifdef OLD
    /* look for Content_Length: */
    if (IS_SERVER(ptcp) && (ph->content_length == 0)) {
	for (pch = pdata; pch <= (char *)plast; ++pch) {
	    if (strncasecmp(pch,"Content-Length:", 15) == 0) {
		/* find the value */
		ph->content_length = atoi(&pch[16]);
	    }
	}
    }

    /* at least count the bytes */
    if (IS_SERVER(ptcp)) {
	ph->byte_count += tcp_data_length;
    }

#endif
