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
static char const rcsid[] =
   "$Header$";


#ifdef LOAD_MODULE_HTTP

#include "tcptrace.h"
#include <sys/mman.h>
#include "mod_http.h"


#define DEFAULT_SERVER_PORT 80


/* Revised HTTP module with a new HTTP parser provided by Bruce Mah */

/* codes for different message types */
typedef enum {
     MethodCodeOptions,
     MethodCodeGet,
     MethodCodeHead,
     MethodCodePost,
     MethodCodePut,
     MethodCodeDelete,
     MethodCodeTrace,
     MethodCodeUnknown
} MethodCode;

char *MethodCodeString[] = {
     "OPTIONS",
     "GET",
     "HEAD",
     "POST",
     "PUT",
     "DELETE",
     "TRACE"
};

/* info gathered for each GET */
struct get_info {
    timeval get_time;		/* when CLIENT sent GET */
    timeval send_time;		/* when SERVER sent CONTENT */
    timeval lastbyte_time;	/* when SERVER sent last byte of CONTENT */
    timeval ack_time;		/* when CLIENT acked CONTENT */
    unsigned request_position;  /* byte offset for this request */
    unsigned reply_position;    /* byte offset for this reply */
    MethodCode method;          /* HTTP method code */
    unsigned response_code;     /* HTTP response code */
    unsigned content_length;	/* as reported by server */
    char *get_string;		/* content of GET string */
    char *content_type;         /* MIME type */  

    struct get_info *next;
};



/* linked list of times */
struct time_stamp {
    timeval 	       thetime;
    u_long 	       position;
    struct time_stamp *next;
    struct time_stamp *prev;
};


/* info kept for each client */
static struct client_info {
    PLOTTER plotter;
    char *clientname;
    struct client_info *next;
} *client_head = NULL;


/* info kept for each connection */
static struct http_info {
    timeval c_syn_time;		/* when CLIENT sent SYN */
    timeval s_syn_time;		/* when SERVER sent SYN */
    timeval c_fin_time;		/* when CLIENT sent FIN */
    timeval s_fin_time;		/* when SERVER sent FIN */

    /* client record */
    struct client_info *pclient;

    /* info about the TCP connection */
    tcp_pair *ptp;
    tcb *tcb_client;
    tcb *tcb_server;

    /* aggregate statistics for HTTP requests on this connection*/
    /* some of this info is available in *tcb_client and *tcb_server */
    /* but we keep a copy of it here to keep all useful info in one place */
    unsigned total_request_length;
    unsigned total_reply_length;
    unsigned total_request_count;
    unsigned total_reply_count;
   
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
} *httphead = NULL, *httptail = NULL;



/* which port are we monitoring?? */
static unsigned httpd_port;


/* local routines */
static timeval WhenSent(struct time_stamp *phead, struct time_stamp *ptail,
			u_long position);
static timeval WhenAcked(struct time_stamp *phead, struct time_stamp *ptail,
			 u_long position);
static void MFUnMap(MFILE *mf, char *firstbyte);
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
static void HttpDoPlot(void);
static struct client_info *FindClient(char *clientname);


/* useful macros */
#define IS_CLIENT(ptcp) (ntohs((ptcp)->th_dport) == httpd_port)
#define IS_SERVER(ptcp) (ntohs((ptcp)->th_dport) != httpd_port)


/* Mostly as a module example, here's a plug in that records HTTP info */
int
http_init(
    int argc,
    char *argv[])
{
    int i;
    int enable=0;

    /* look for "-xhttp[N]" */
    for (i=1; i < argc; ++i) {
	if (!argv[i])
	    continue;  /* argument already taken by another module... */
	if (strncmp(argv[i],"-x",2) == 0) {
	    if (strncasecmp(argv[i]+2,"http",4) == 0) {
		/* I want to be called */
		enable = 1;
		if (isdigit((int)(argv[i][6]))) {
		    httpd_port = atoi(argv[i]+6);
		} else {
		    httpd_port = DEFAULT_SERVER_PORT;
		}
		printf("mod_http: Capturing HTTP traffic (port %d)\n", httpd_port);
		argv[i] = NULL;
	    }
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

    if (debug>1)
	fprintf(stderr,"DataOffset: seq is %lu, syn is %lu, offset is %ld\n",
		seq, tcb->syn, off);

    return(off);
}


static struct get_info *
MakeGetRec(
    struct http_info *ph)
{
    struct get_info *pg;

    pg = MallocZ(sizeof(struct get_info));
   
    /* initialize some fields */
    pg->get_string = "- -";
    pg->content_type = "-/-";  

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

    /* chain it in (at the tail of the list) */
    if (httphead == NULL) {
	httphead = ph;
	httptail = ph;
    } else {
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


static struct client_info *
FindClient(
    char *clientname)
{
    struct client_info *p;

    for (p=client_head; p; p = p->next) {
	if (strcmp(clientname,p->clientname)==0) {
	    return(p);
	}
    }

    /* else, make one up */
    p = MallocZ(sizeof(struct client_info));
    p->next = client_head;
    client_head = p;
    p->clientname = strdup(clientname);
    p->plotter = NO_PLOTTER;

    return(p);
}



void
http_read(
    struct ip *pip,		/* the packet */
    tcp_pair *ptp,		/* info I have about this connection */
    void *plast,		/* past byte in the packet */
    void *mod_data)		/* module specific info for this connection */
{
    struct tcphdr *ptcp;
    unsigned tcp_length;
    unsigned tcp_data_length;
    char *pdata;
    struct http_info *ph = mod_data;

    /* find the start of the TCP header */
    ptcp = (struct tcphdr *) ((char *)pip + 4*IP_HL(pip));
    tcp_length = ntohs(pip->ip_len) - (4 * IP_HL(pip));
    tcp_data_length = tcp_length - (4 * TH_OFF(ptcp));

    /* verify port */
    if ((ntohs(ptcp->th_sport) != httpd_port) && (ntohs(ptcp->th_dport) != httpd_port))
	return;

    /* find the data */
    pdata = (char *)ptcp + (unsigned)TH_OFF(ptcp)*4;

    /* for client, record both ACKs and DATA time stamps */
    if (ph && IS_CLIENT(ptcp)) {
	if (tcp_data_length > 0) {
	    AddGetTS(ph,DataOffset(ph->tcb_client,ntohl(ptcp->th_seq)));
	}
	if (ACK_SET(ptcp)) {
	    if (debug > 4)
		printf("Client acks %ld\n", DataOffset(ph->tcb_server,ntohl(ptcp->th_ack)));	    
	    AddAckTS(ph,DataOffset(ph->tcb_server,ntohl(ptcp->th_ack)));
	}
    }

    /* for server, record DATA time stamps */
    if (ph && IS_SERVER(ptcp)) {
	if (tcp_data_length > 0) {
	    AddDataTS(ph,DataOffset(ph->tcb_server,ntohl(ptcp->th_seq)));
	    if (debug > 5) {
		printf("Server sends %ld thru %ld\n",
		       DataOffset(ph->tcb_server,ntohl(ptcp->th_seq)),
		       DataOffset(ph->tcb_server,ntohl(ptcp->th_seq))+tcp_data_length-1);
	    }
	}
    }

    
    /* we also want the time that the FINs were sent */
    if (ph && FIN_SET(ptcp)) {
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
    if (ph && SYN_SET(ptcp)) {
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

    if (len == 0) {
      *firstbyte = NULL;
      *lastbyte = NULL;
      return;
    }
  
    /* Memory map the entire file */
    fd = Mfileno(mf);
    vaddr = mmap((caddr_t) 0,	/* put it anywhere	*/
		 len,		/* fixed size		*/
		 PROT_READ,	/* read only		*/
		 MAP_PRIVATE,	/* won't be sharing...	*/
		 fd,		/* attach to 'fd'	*/
		 (off_t) 0);	/* ... offset 0 in 'fd'	*/
    if (vaddr == (char *) -1) {
	perror("mmap");
	exit(-1);
    }

    *firstbyte = vaddr;
    *lastbyte = vaddr+len-1;

    return;
}



static void
MFUnMap(
    MFILE *mf,
    char *firstbyte)
{
    int fd;
    int len;
    
    /* find length of file */
    if (Mfseek(mf,0,SEEK_END) != 0) {
	perror("fseek");
	exit(-1);
    }
    len = Mftell(mf);

    /* unmap it */
    fd = Mfileno(mf);
    if (munmap(firstbyte,len) != 0) {
	perror("munmap");
	exit(-1);
    }

    return;
}


static void
HttpGather(
    struct http_info *ph)
{
    while (ph) {
	if (ph->tcb_client->extr_contents_file &&
	    ph->tcb_server->extr_contents_file)
	{
	    FindGets(ph);
	    FindContent(ph);
	}

	ph = ph->next;
    }
}


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

    if (debug > 10) {
	printf("pos:%ld, Chain:\n", position);
	PrintTSChain(phead,ptail);
    }

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

    if (debug > 10) {
	printf("pos:%ld, Chain:\n", position);
	PrintTSChain(phead,ptail);
    }

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
    MFILE *mf = tcb->extr_contents_file;
    char *pdata;
    char *plast;
    char *pch;
    char *pch2;
    struct get_info *pget;
    char getbuf[1024];
    u_long position = 0;
    unsigned last_position = 0;
    int done;
    int i;
    typedef enum {
       ContentStateStartHttp,
       ContentStateFinishHttp,
       ContentStateFindResponse,
       ContentStateFindContentLength,
       ContentStateFinishHeader} StateType;
    StateType state;

    pget = ph->gets_head;
    if ((mf) && (pget)) {
 
       state = ContentStateStartHttp;
       done = 0;

       /* Memory map the entire file (I hope it's short!) */
       MFMap(mf,&pdata,&plast);
      
       if (pdata == NULL) {
	 return;
       }
      
       pch = pdata;
       
       ph->total_reply_length = (unsigned) (plast - pdata);
       ph->total_reply_count= 0;
       
       while ((!done) && (pch <= (char *) plast)) {
           switch (state) {

	    /* Start state: Find "HTTP/" that begins a response */
	    case (ContentStateStartHttp): {
	       if (strncasecmp(pch, "HTTP/", 5) == 0) {

		  /* Found start of a response */
		  state = ContentStateFinishHttp;
		  position = pch - pdata + 1;
		  pget->reply_position = position;
		  pch += 5;
	       }
	       else {
		  pch++;
	       }
	    }
	      break;

	    /* Finish off HTTP string (version number) by looking for whitespace */
	    case (ContentStateFinishHttp): {
	       if (*(pch) == ' ') {
		  state = ContentStateFindResponse;
	       }
	       else {
		  pch++;
	       }
	    }
	      break;
	      
	    /* Look for response code by finding non-whitespace. */
	    case (ContentStateFindResponse): {
	       if (*(pch) != ' ') {
		  pget->response_code = atoi(pch);
		  pch += 3;
		  state = ContentStateFindContentLength;
	       }
	       else {
		  pch++;
	       }
	    }
	      break;
	      
	    /* this state is now misnamed since we pull out other */
	    /* headers than just content-length now. */
	    case (ContentStateFindContentLength): {
	       if (strncasecmp(pch, "\r\nContent-Length:", 17) == 0) {
		  /* Got content-length field, ignore rest of header */
		  pget->content_length = atoi(&(pch[17]));
		  pch += 18;
	       }
	       else if (strncasecmp(pch, "\r\nContent-Type:", 15) == 0) {
		  /* Get content-type field, skipping leading spaces */
		  pch += 15;
		  while (*pch == ' ') {
		     pch++;
		  }
		  for (i=0,pch2 = pch; ; ++i, ++pch2) {
		     if ((*pch2 == '\n') || (*pch2 == '\r') ||
			 (i >= sizeof(getbuf)-1)) {
			getbuf[i] = '\00';
			pch = pch2;  /* skip forward */
			break;
		     }
		     getbuf[i] = *pch2;
		  }
		  
		  /* If there are any spaces in the Content-Type */
		  /* field, we need to truncate at that point */
		    {
		       char *sp;
		       sp = (char *)index(getbuf, ' ');
		       if (sp) {
			  *sp = '\00';
		       }
		    }
		  pget->content_type = strdup(getbuf);
		  
	       }
	       else if (strncmp(pch, "\r\n\r\n", 4) == 0) {
		  /* No content-length header detected */
		  /* No increment for pch here, effectively fall through */
		  /* pget->content_length = 0; */
		  state = ContentStateFinishHeader;
	       }
	       else {
		  pch++;
	       }
	    }
	      break;
	      
	    /* Skip over the rest of the header */
	    case (ContentStateFinishHeader): {
	       if (strncmp(pch, "\r\n\r\n", 4) == 0) {
		  
		  /* Found end of header */
		  pch += 4;
		  
		  /*
		   * At this point, we need to find the end of the
		   * response body.  There's a variety of ways to
		   * do this, but in any case, we need to make sure
		   * that pget->content_length, pch, and last_postiion
		   * are all set appropriately.
		   *
		   * See if we can ignore the body.  We can do this
		   * for the reply to HEAD, for a 204 (no content),
		   * 205 (reset content), or 304 (not modified).
		   */
		  if ((pget->method == MethodCodeHead) ||
		      (pget->response_code == 204) ||
		      (pget->response_code == 205) ||
		      (pget->response_code == 304)) {
		     pget->content_length = 0;
		  }
		  
		  /*
		   * Use content-length header if one was present.
		   * XXX is content_length > 0 the right test?
		   */
		  else if (pget->content_length > 0) {
		     pch += pget->content_length;
		  }
		  
		  /*
		   * No content-length header, so delimit response
		   * by end of file.
		   * 
		   * But, make sure we do not have a "\r\n\r\n" string
		   * in the response, because that might indicate the 
		   * beginning of a following response.
		   * (Patch from Yufei Wang)
		   */
		  else {
		   char *start = pch;
		   while (pch <= (char *)plast) {
		     if (strncmp(pch, "\r\n\r\n", 4) == 0) {
		       pch += 4;
		       state = ContentStateStartHttp;
		       break;
		     } else {
		       pch++;
		     }
		   } 
		   
		   if (state == ContentStateStartHttp) {
		     pget->content_length = pch - start;
		   } else {
		     /* calculate the content length */
		     pget->content_length = plast - start + 1;
		     pch = plast + 1;
		   }
		  }
		 
		  /* Set next state and do original tcptrace
		   * processing based on what we learned above.
		   */
		  state = ContentStateStartHttp;
		  last_position = pch - pdata + 1;
		  
		  /* when was the first byte sent? */
		  pget->send_time = WhenSent(&ph->data_head,&ph->data_tail,position);
		  
		  /* when was the LAST byte sent? */
		  pget->lastbyte_time = WhenSent(&ph->data_head,&ph->data_tail,last_position);
		  
		  /* when was the last byte ACKed? */
		  if (debug > 4)
		    printf("Content length: %d\n", pget->content_length);
		  pget->ack_time = WhenAcked(&ph->ack_head,&ph->ack_tail,last_position);

		  /* increment our counts */
		  ph->total_reply_count++;

		  /* skip to the next request */
		  pget = pget->next;

		  if (!pget) {
		     /* no more questions, quit */
		     done = 1;
		     break;
		  }
	       }
	       else {
		  pch++;
	       }
	    }
	      break;
	      
	   }
       }
       
       MFUnMap(mf,pdata);
    }
   else {
      if (debug > 4) {
	 printf("FindContent() with null server contents");
      }
   }
   
}

static char * formatGetString(char * s) 
{
  int len = strlen(s);
  int i = 0;
  int j = 0;
  char *buf = (char *)malloc(len);
  char ascii[2];
  while (i < len) {
    if (s[i] == '%') {
      ascii[0] = s[i+1];
      ascii[1] = s[i+2];
      buf[j++] = atoi(ascii);
      i = i+3;
    } else {
      buf[j++] = s[i];
      i++;
    }
  }
  buf[j] = 0;
  return buf;
}

static void
FindGets(
    struct http_info *ph)
{
    tcb *tcb = ph->tcb_client;
    MFILE *mf = tcb->extr_contents_file;
    char *pdata;
    char *plast;
    char *pch;
    char *pch2;
    struct get_info *pget = NULL;
    char getbuf[1024];
    u_long position = 0;
    int j;
    int methodlen;
    unsigned long long contentLength = 0;

     typedef enum {
       GetStateStartMethod,
       GetStateFinishMethod,
       GetStateFindContentLength,
       GetStateFinishHeader
     } StateType;
     StateType state;

   if (mf) {

      /* Memory map the entire file (I hope it's short!) */
      MFMap(mf,&pdata,&plast);

      if (pdata == NULL) {
	return;
      }
	
      ph->total_request_length = (unsigned) (plast - pdata);
      ph->total_request_count = 0;
      
      state = GetStateStartMethod;
      
      /* search for method string*/
      pch = pdata;
      while (pch <= (char *)plast) {
	  switch (state) {
	     
	  /* Start state: Find access method keyword */
	  case (GetStateStartMethod): {
	     
	  /* Try to find a word describing a method.  These
	   * are all the methods defined in
           * draft-ietf-http-v11-spec-rev-06
	   */
	     MethodCode method = MethodCodeUnknown;
	     methodlen = 0;
	     if (strncasecmp(pch, "options ", 8) == 0) {
		methodlen = 8;
		method = MethodCodeOptions;
	     }
	     else if (strncasecmp(pch, "get ", 4) == 0) {
		methodlen = 4;
		method = MethodCodeGet;
	     }
	     else if (strncasecmp(pch, "head ", 5) == 0) {
		methodlen = 5;
		method = MethodCodeHead;
	     }
	     else if (strncasecmp(pch, "post ", 5) == 0) {
		methodlen = 5;
		method = MethodCodePost;
	     }
	     else if (strncasecmp(pch, "put ", 4) == 0) {
		methodlen = 4;
		method = MethodCodePut;
	     }
	     else if (strncasecmp(pch, "delete ", 7) == 0) {
		methodlen = 7;
		method = MethodCodeDelete;
	     }
	     else if (strncasecmp(pch, "trace ", 6) == 0) {
		methodlen = 6;
		method = MethodCodeTrace;
	     }
	     
	     if (methodlen > 0) {
		/* make a new record for this entry */
		pget = MakeGetRec(ph);
		
		/* remember where it started */
		position = pch - pdata + 1;
		pget->request_position = position;
		pget->reply_position = 0;
		pget->method = method;
		
		contentLength = 0;
		pch += methodlen;
		state = GetStateFinishMethod;
	     }
	     else {
		/* Couldn't find a valid method, so increment */
		/* and attempt to resynchronize.  This shouldn't */
		/* happen often. */
		pch++;
	     }
	     
	  };
	    break;
	    
	  case (GetStateFinishMethod): {
	     /* grab the GET string */
	     for (j=0,pch2 = pch; ; ++j,++pch2) {
		if ((*pch2 == '\n') || (*pch2 == '\r') ||
		    (j >= sizeof(getbuf)-1)) {
		   getbuf[j] = '\00';
		   pch = pch2;  /* skip forward */
		   state = GetStateFindContentLength;
		   break;
		}
		getbuf[j] = *pch2;
	     }
	     pget->get_string = formatGetString(getbuf);
	     
	     /* grab the time stamps */
	     pget->get_time =
	       WhenSent(&ph->get_head,&ph->get_tail,position);
	     ph->total_request_count++;
	     
	  }
	     break;
	     
	  /* Locate content-length field, if any */
	   case (GetStateFindContentLength): {
	      
	      if (strncasecmp(pch, "\r\nContent-Length:", 17) == 0) {
		 /* Get content-length field */
		 contentLength = atoi(&pch[17]);
		 pch += 17;
	      }
	      else if (strncmp(pch, "\r\n\r\n", 4) == 0) {
		 /* No content-length header detected, assume */
		 /* zero.  Fall through (effective). */
		 /* contentLength = 0; */
		 state = GetStateFinishHeader;
	      }
	      else {
		 pch++;
	      }
	   }
	     break;
	     
	  case (GetStateFinishHeader): {
	     if (strncmp(pch, "\r\n\r\n", 4) == 0) {
		
		/* Found end of header */
		pch += 4;
		
		/* Find end of response body. */
		if (contentLength > 0) {
		   pch += contentLength;
		}
		else {
		   /* XXX What if a POST with no content-length? */
		}
		
		state = GetStateStartMethod;
	     }
	     else {
		pch++;
	     }
	  }
	     break;
	  }
      }
            
      MFUnMap(mf,pdata);
   }
   
   else {
      if (debug > 4) {
	 printf("FindGets() with null client contents");
      }
   }
}


static void
HttpDoPlot()
{
    struct http_info *ph;
    struct get_info *pget;
    int y_axis = 1000;
    int ix_color = 0;
    char buf[100];
    struct time_stamp *pts;

    /* sort by increasing order of TCP connection startup */
    /* (makes the graphs look better) */

    for (ph=httphead; ph; ph=ph->next) {
	PLOTTER p = ph->pclient->plotter;
	tcp_pair *ptp = ph->ptp;
	tcb a2b, b2a;

	if (ptp == NULL)
	    continue;

	a2b = ptp->a2b;
	b2a = ptp->b2a;

	ix_color = (ix_color + 1) % NCOLORS;

	/* find the plotter for this client */
	if (p==NO_PLOTTER) {
	    char title[256];
	    snprintf(title, sizeof(title), "Client %s HTTP trace\n", ph->pclient->clientname); 
	    p = ph->pclient->plotter =
		new_plotter(&ptp->a2b,
			    ph->pclient->clientname,	/* file name prefix */
			    title,			/* plot title */
			    "time", 			/* X axis */
			    "URL",			/* Y axis */
			    "_http.xpl");		/* file suffix */
	}

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
		     (snprintf(buf, sizeof(buf), "%s ==> %s",
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
	    plotter_text(p,ph->s_syn_time,y_axis,"a","Serv SYN");
	}

	/* plot the FINs */
	if (!ZERO_TIME(&ph->c_fin_time)) {
	    plotter_tick(p,ph->c_fin_time,y_axis,'u');
	    plotter_text(p,ph->c_fin_time,y_axis,"a","Clnt FIN");
	}
	if (!ZERO_TIME(&ph->s_fin_time)) {
	    plotter_tick(p,ph->s_fin_time,y_axis,'u');
	    plotter_text(p,ph->s_fin_time,y_axis,"a","Serv FIN");
	}

	y_axis += 4;

	for (pget = ph->gets_head; pget; pget = pget->next) {

	    if (ZERO_TIME(&pget->send_time) ||
		ZERO_TIME(&pget->get_time) ||
		ZERO_TIME(&pget->ack_time))
		continue;
	    
	    plotter_temp_color(p,"white");
	    plotter_text(p, pget->get_time, y_axis, "l", pget->get_string);

	    plotter_diamond(p, pget->get_time, y_axis);
	    plotter_larrow(p, pget->send_time, y_axis);
	    plotter_rarrow(p, pget->lastbyte_time, y_axis);
	    plotter_line(p,
			 pget->send_time, y_axis,
			 pget->lastbyte_time, y_axis);
	    plotter_temp_color(p,"white");
	    plotter_text(p, pget->lastbyte_time, y_axis, "r",
			 (snprintf(buf, sizeof(buf), "%d",pget->content_length),buf));
	    plotter_diamond(p, pget->ack_time, y_axis);
#ifdef CLUTTERED
	    plotter_temp_color(p,"white");
	    plotter_text(p, pget->ack_time, y_axis, "b", "ACK");
#endif  /* CLUTTERED */

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
    struct get_info *pget = NULL;
    u_long missing;
    double etime;

    if (!ptp)
	return;
	
    printf("%s ==> %s (%s2%s)\n",
	   ptp->a_endpoint, ptp->b_endpoint,
	   ptp->a2b.host_letter, ptp->b2a.host_letter);

    printf("  Server Syn Time:      %s (%.3f)\n",
	   ts2ascii(&ph->s_syn_time),
	   ts2d(&ph->s_syn_time));
    printf("  Client Syn Time:      %s (%.3f)\n",
	   ts2ascii(&ph->c_syn_time),
	   ts2d(&ph->c_syn_time));
  
   /* From the patch by Yufei Wang
    * Print "Server Rst Time" if the last segment we saw was a RST
    *       "Server Fin Time" if we saw a FIN
    *       "Server Last Time" if neither FIN/RST was received to indicate
    *                          the time the last segment was seen from the
    *                          server. */

   if ((pba->fin_count == 0) && (pba->reset_count > 0)) {
	printf("  Server Rst Time:      %s (%.3f)\n",
		ts2ascii(&pba->last_time),
		ts2d(&pba->last_time));
    } else if (pba->fin_count == 0) {
	printf("  Server Last Time:      %s (%.3f)\n",
	       ts2ascii(&pba->last_time),
	       ts2d(&pba->last_time));
    } else {
    	printf("  Server Fin Time:      %s (%.3f)\n",
	   	ts2ascii(&ph->s_fin_time),
	   	ts2d(&ph->s_fin_time));
    }
    /* Similarly information is printed out for the Client end-point.*/	
    if ((pab->fin_count == 0) && (pab->reset_count > 0)) {
	printf("  Client Rst Time:      %s (%.3f)\n",
		ts2ascii(&pab->last_time),
		ts2d(&pab->last_time));
    } else if (pab->fin_count == 0) {
	printf("  Client Last Time:      %s (%.3f)\n",
		ts2ascii(&pab->last_time),
		ts2d(&pab->last_time));
    } else {
    	printf("  Client Fin Time:      %s (%.3f)\n",
	   	ts2ascii(&ph->c_fin_time),
	   	ts2d(&ph->c_fin_time));
    }

#ifdef HTTP_SAFE
    /* check the SYNs */
    if ((pab->syn_count == 0) || (pba->syn_count == 0)) {
	printf("\
No additional information available, beginning of \
connection (SYNs) were not found in trace file.\n");
	return;      
    }

    /* check if we had RSTs (Patch from Yufei Wang)*/
    if ((pab->reset_count > 0) || (pba->reset_count > 0)) {
      /* Do nothing */
    }
      /* check the FINs */
      /* Note from Yufei Wang : If we see a FIN from only one direction,
       * we shall not panic, but print out information that we have under the
       * assumption that either a RST was sent in the missing direction or the
       * FIN segment was lost from packet capture. The information we have
       * is still worth printing out. Hence we have a "&&" instead of a "||"
       * in the following condition. */
      else if ((pab->fin_count == 0) && (pba->fin_count == 0)) {
	printf("\
No additional information available, end of \
connection (FINs) were not found in trace file.\n");
	return;
    }
#endif /* HTTP_SAFE */

    /* see if we got all the bytes */
    missing = pab->trunc_bytes + pba->trunc_bytes;

    /* Patch from Yufei Wang :
     * Adding in a check to see if the connection were closed with RST/FIN 
     * and calculating the "missing" field appropriately
     */
  
    if (pab->fin_count > 0)
      missing += ( (pab->fin - pab->syn -1)- pab->unique_bytes);
    else if (pab->reset_count > 0) {
      /* Check to make sure if no segments were observed between SYN and RST
       * The following check does not work if file is huge and seq space rolled
       * over - To be fixed - Mani */
      if (pab->latest_seq != pab->syn)
	missing += ( (pab->latest_seq - pab->syn -1) - pab->unique_bytes);
    }
  
    if (pba->fin_count > 0)
      missing += ( (pba->fin - pba->syn -1)- pba->unique_bytes);
    else if (pba->reset_count > 0) {
      /* Check to make sure if no segments were observed between SYN and RST
       * The following check does not work if file is huge and seq space rolled
       * over - To be fixed - Mani */
      if (pba->latest_seq != pba->syn)
	missing += ( (pba->latest_seq - pba->syn -1) - pba->unique_bytes);
    }
  
    if (missing != 0)
	printf("WARNING!!!!  Information may be invalid, %ld bytes were not captured\n",
	       missing);

#ifdef HTTP_DUMP_TIMES

     Mfprintf(pmf, "conn %s %s %s2%s %u %u %u %u\n",
            ptp->a_endpoint,
            ptp->b_endpoint,
            ptp->a2b.host_letter, ptp->b2a.host_letter,
            ph->total_request_length,
            ph->total_request_count,
            ph->total_reply_length,
            ph->total_reply_count);

#endif /* HTTP_DUMP_TIMES */
   
   for (pget = ph->gets_head; pget; pget = pget->next) {
      
      unsigned request_length = 0;
      unsigned reply_length = 0;
      
      /* Compute request lengths */
      if (pget->next) {
	 
	 /* Retrieval following ours, use its position to compute our length */
	 request_length = pget->next->request_position - pget->request_position;
      }
      else {
	 
	 /* Last one in this file, so use the EOF as a delimiter */
	 request_length = ph->total_request_length - pget->request_position;
      }
      
      /* Compute reply lengths */
      if (pget->reply_position == 0) {
	 /* No reply, so length is 0 by definition */
	 request_length = 0;
      }
      else {
	 if ((pget->next) && (pget->next->reply_position > 0)) {
	    /* Retrieval following ours with valid position, so use that to compute length */
	    reply_length = pget->next->reply_position - pget->reply_position;
	 }
	 else {
	    /* No record following ours, or it didn't have a valid position, so use EOF as delimiter */
	    reply_length = ph->total_reply_length - pget->reply_position;
	 }
      }
      
      printf("    %s %s\n", MethodCodeString[pget->method],
	     pget->get_string);
      
      /* Interpretation of response codes as per RFC 2616 - HTTP/1.1 */
      switch (pget->response_code) {
	 /* Informational 1xx */
       case 100 :
	 printf("\tResponse Code:       %d (Continue)\n", pget->response_code);
	 break;
       case 101 :
	 printf("\tResponse Code:       %d (Switching Protocols)\n", pget->response_code);
	 break;	 
	 
	 /* Successful 2xx */
       case 200 :
	 printf("\tResponse Code:       %d (OK)\n", pget->response_code);
	 break;	 
       case 201 :
	 printf("\tResponse Code:       %d (Created)\n", pget->response_code);
	 break;	 
       case 202 :
	 printf("\tResponse Code:       %d (Accepted)\n", pget->response_code);
	 break;	 
       case 203 :
	 printf("\tResponse Code:       %d (Non-Authoritative Information)\n", pget->response_code);
	 break;	 
       case 204 :
	 printf("\tResponse Code:       %d (No Content)\n", pget->response_code);
	 break;	 
       case 205 :
	 printf("\tResponse Code:       %d (Reset Content)\n", pget->response_code);
	 break;	 
       case 206 :
	 printf("\tResponse Code:       %d (Partial Content)\n", pget->response_code);
	 break;
	 
	 /* Redirection 3xx */
       case 300 :
	 printf("\tResponse Code:       %d (Multiple Choices)\n", pget->response_code);
	 break;	 
       case 301 :
	 printf("\tResponse Code:       %d (Moved Permanently)\n", pget->response_code);
	 break;	 
       case 302 :
	 printf("\tResponse Code:       %d (Found)\n", pget->response_code);
	 break;	 
       case 303 :
	 printf("\tResponse Code:       %d (See Other)\n", pget->response_code);
	 break;	 
       case 304 :
	 printf("\tResponse Code:       %d (Not Modified)\n", pget->response_code);
	 break;	 
       case 305 :
	 printf("\tResponse Code:       %d (Use Proxy)\n", pget->response_code);
	 break;	 
       case 306 :
	 printf("\tResponse Code:       %d (Unused)\n", pget->response_code);
	 break;
       case 307 :
	 printf("\tResponse Code:       %d (Temporary Redirect)\n", pget->response_code);
	 break;	 

	 /* Client Error 4xx */
       case 400 :
	 printf("\tResponse Code:       %d (Bad Request)\n", pget->response_code);
	 break;	 
       case 401 :
	 printf("\tResponse Code:       %d (Unauthorized)\n", pget->response_code);
	 break;	 
       case 402 :
	 printf("\tResponse Code:       %d (Payment Required)\n", pget->response_code);
	 break;	 
       case 403 :
	 printf("\tResponse Code:       %d (Forbidden)\n", pget->response_code);
	 break;	 
       case 404 :
	 printf("\tResponse Code:       %d (Not Found)\n", pget->response_code);
	 break;	 
       case 405 :
	 printf("\tResponse Code:       %d (Method Not Allowed)\n", pget->response_code);
	 break;	 
       case 406 :
	 printf("\tResponse Code:       %d (Not Acceptable)\n", pget->response_code);
	 break;	 
       case 407 :
	 printf("\tResponse Code:       %d (Proxy Authentication Required)\n", pget->response_code);
	 break;	 
       case 408 :
	 printf("\tResponse Code:       %d (Request Timeout)\n", pget->response_code);
	 break;	 
       case 409 :
	 printf("\tResponse Code:       %d (Conflict)\n", pget->response_code);
	 break;	 
       case 410 :
	 printf("\tResponse Code:       %d (Gone)\n", pget->response_code);
	 break;	 
       case 411 :
	 printf("\tResponse Code:       %d (Length Required)\n", pget->response_code);
	 break;	 
       case 412 :
	 printf("\tResponse Code:       %d (Precondition Failed)\n", pget->response_code);
	 break;	 
       case 413 :
	 printf("\tResponse Code:       %d (Request Entity Too Large)\n", pget->response_code);
	 break;	 
       case 414 :
	 printf("\tResponse Code:       %d (Request-URI Too Long)\n", pget->response_code);
	 break;	 
       case 415 :
	 printf("\tResponse Code:       %d (Unsupported Media Type)\n", pget->response_code);
	 break;	 
       case 416 :
	 printf("\tResponse Code:       %d (Requested Range Not Satisfiable)\n", pget->response_code);
	 break;	 
       case 417:
	 printf("\tResponse Code:       %d (Expectation Failed)\n", pget->response_code);
	 break;
	 
	 /* Server Error 5xx */
       case 500 :
	 printf("\tResponse Code:       %d (Internal Server Error)\n", pget->response_code);
	 break;	 
       case 501 :
	 printf("\tResponse Code:       %d (Not Implemented)\n", pget->response_code);
	 break;	 
       case 502 :
	 printf("\tResponse Code:       %d (Bad Gateway)\n", pget->response_code);
	 break;	 
       case 503 :
	 printf("\tResponse Code:       %d (Service Unavailable)\n", pget->response_code);
	 break;	 
       case 504 :
	 printf("\tResponse Code:       %d (Gateway Timeout)\n", pget->response_code);
	 break;	 
       case 505 :
	 printf("\tResponse Code:       %d (HTTP Version Not Supported)\n", pget->response_code);
	 break;	 
	   
       default :
	 printf("\tResponse Code:       %d (unknown response code)\n", pget->response_code);

      }
      
      printf("\tRequest Length:      %u\n", request_length);
      printf("\tReply Length:        %u\n", reply_length);
      printf("\tContent Length:      %d\n", pget->content_length);
      printf("\tContent Type  :      %s\n", pget->content_type);
      printf("\tTime request sent:   %s (%.3f)\n",
	     ts2ascii(&pget->get_time), ts2d(&pget->get_time));
      printf("\tTime reply started:  %s (%.3f)\n",
	     ts2ascii(&pget->send_time), ts2d(&pget->send_time));
      printf("\tTime reply ACKed:    %s (%.3f)\n",
	     ts2ascii(&pget->ack_time), ts2d(&pget->ack_time));
      
      /* elapsed time, request started to answer started */
      etime = elapsed(pget->get_time,pget->send_time);
      etime /= 1000;  /* us to msecs */
      printf("\tElapsed time:  %.0f ms (request to first byte sent)\n", etime);
      
      /* elapsed time, request started to answer ACKed */
      etime = elapsed(pget->get_time,pget->ack_time);
      etime /= 1000;  /* us to msecs */
      printf("\tElapsed time:  %.0f ms (request to content ACKed)\n", etime);
      
#ifdef HTTP_DUMP_TIMES
      Mfprintf(pmf,"reqrep %s %s %s2%s %.3f %.3f %.3f %u %u %3d %s %s %s\n",
	       ptp->a_endpoint,
	       ptp->b_endpoint,
	       ptp->a2b.host_letter, ptp->b2a.host_letter,
	       ts2d(&pget->get_time),
	       ts2d(&pget->send_time),
	       ts2d(&pget->ack_time),
	       request_length,
	       reply_length,
	       pget->response_code,
	       MethodCodeString[pget->method],
	       pget->get_string,
	       pget->content_type);
#endif /* HTTP_DUMP_TIMES */
      
   }
   
}

void
http_done(void)
{
    MFILE *pmf = NULL;
    struct http_info *ph;

    /* just return if we didn't grab anything */
    if (!httphead)
	return;

    /* gather up the information */
    HttpGather(httphead);

#ifdef HTTP_DUMP_TIMES
    pmf = Mfopen("http.times","w");
#endif /* HTTP_DUMP_TIMES */

    printf("Http module output:\n");

    for (ph=httphead; ph; ph=ph->next) {
	HttpPrintone(pmf,ph);
    }

    HttpDoPlot();

#ifdef HTTP_DUMP_TIMES
    Mfclose(pmf);
#endif /* HTTP_DUMP_TIMES */
}


void
http_usage(void)
{
    printf("\t-xHTTP[P]\tprint info about http traffic (on port P, default %d)\n",
	   DEFAULT_SERVER_PORT);
}



void
http_newfile(
    char *newfile,
    u_long filesize,
    Bool fcompressed)
{
    /* just an example, really */
}



void *
http_newconn(
    tcp_pair *ptp)
{
    struct http_info *ph;

    ph = MakeHttpRec();

    /* attach tcptrace's info */
    ph->ptp = ptp;
 
    /* determine the server and client tcb's */
    if (ptp->addr_pair.a_port == httpd_port) {
	ph->tcb_client = &ptp->b2a;
	ph->tcb_server = &ptp->a2b;
    } else {
	ph->tcb_client = &ptp->a2b;
	ph->tcb_server = &ptp->b2a;
    }
 
    /* attach the client info */
    ph->pclient = FindClient(HostName(ptp->addr_pair.a_address));

    return(ph);
}
#endif /* LOAD_MODULE_HTTP */
