/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *               2002, 2003, 2004
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
 * Author:	Eric Helvey
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ehelvey@cs.ohiou.edu
 *		http://www.tcptrace.org/
 */
static char const GCC_UNUSED rcsid_tcplib[] =
    "@(#)$Header$";


/* header file for mod_tcplib.c */
int tcplib_init(int argc, char *argv[]);
void tcplib_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmodstruct);
void tcplib_done(void);
void tcplib_usage(void);
void tcplib_newfile(char *filename, u_long filesize, Bool fcompressed);
void * tcplib_newconn(tcp_pair *ptp);


/* various ports that we need to find */
#define IPPORT_FTP_DATA 20
#define IPPORT_FTP_CONTROL 21
#define IPPORT_SSH 22
#define IPPORT_TELNET 23
#define IPPORT_SMTP 25
#define IPPORT_OLDLOGIN 49
#define IPPORT_HTTP	80	/* normal */
#define IPPORT_NNTP 119
#define IPPORT_FLN_SPX 221
#define IPPORT_HTTPS	443	/* secure */
#define IPPORT_LOGIN 513
#define IPPORT_UUCP_LOGIN 541
#define IPPORT_KLOGIN 542
#define IPPORT_KLOGIN2 543
#define IPPORT_NLOGIN 758
#define IPPORT_NFS 2049


/* internal breakdown types */
#define NUM_APPS 6
#define TCPLIBPORT_SMTP	   0
#define TCPLIBPORT_NNTP	   1
#define TCPLIBPORT_TELNET  2
#define TCPLIBPORT_FTPCTRL 3
#define TCPLIBPORT_HTTP    4
#define TCPLIBPORT_FTPDATA 5
#define TCPLIBPORT_NONE    -1


#define MAX_TEL_INTER_COUNT 1500000
#define TIMER_VAL  60
#define BREAKDOWN_HASH 1000000


/* data file names */
#define DEFAULT_TCPLIB_DATADIR		"data"
#define TCPLIB_TELNET_DURATION_FILE	"telnet.duration"
#define TCPLIB_TELNET_PACKETSIZE_FILE	"telnet.pktsize"
#define TCPLIB_TELNET_INTERARRIVAL_FILE	"telnet.interarrival"
#define TCPLIB_FTP_ITEMSIZE_FILE	"ftp.itemsize"
#define TCPLIB_FTP_NITEMS_FILE		"ftp.nitems"
#define TCPLIB_FTP_CTRLSIZE_FILE	"ftp.ctlsize"
#define TCPLIB_SMTP_ITEMSIZE_FILE	"smtp.itemsize"
#define TCPLIB_NNTP_BURSTSIZE_FILE	"nntp.burstsize"
#define TCPLIB_NNTP_NITEMS_FILE		"nntp.nitems"
#define TCPLIB_NNTP_IDLETIME_FILE	"nntp.idletime"
#define TCPLIB_BREAKDOWN_FILE		"breakdown"
#define TCPLIB_BREAKDOWN_GRAPH_FILE	"breakdown_hist"
#define TCPLIB_NEXT_CONVERSE_FILE	"conv.conv_time"
#define TCPLIB_CONV_DURATION_FILE	"conv.duration"

/* parallel HTTP */
#define TCPLIB_HTTP_P_IDLETIME_FILE	"http_P.idletime"
#define TCPLIB_HTTP_P_BURSTSIZE_FILE	"http_P.burstsize"
#define TCPLIB_HTTP_P_MAXCONNS_FILE	"http_P.maxconns"
#define TCPLIB_HTTP_P_TTLITEMS_FILE	"http_P.ttlitems"
#define TCPLIB_HTTP_P_PERSIST_FILE	"http_P.persistant"

/* single stream HTTP */
#define TCPLIB_HTTP_S_BURSTSIZE_FILE	"http_S.burstsize"
#define TCPLIB_HTTP_S_IDLETIME_FILE	"http_S.idletime"
#define TCPLIB_HTTP_S_NITEMS_FILE	"http_S.nitems"


/* the granulatity that we store counters */
#define GRAN_BURSTSIZE		256	/* bytes */
#define GRAN_BURSTIDLETIME	10	/* ms */
#define GRAN_CONVDURATION	10	/* ms */
#define GRAN_CONVARRIVAL	1	/* ms */
#define GRAN_TELNET_DURATION	10	/* ms */
#define GRAN_TELNET_ARRIVAL	1	/* ms */
#define GRAN_TELNET_PACKETSIZE	1	/* bytes */
#define GRAN_FTP_ITEMSIZE	256	/* bytes */
#define GRAN_FTP_CTRLSIZE	10	/* bytes */
#define GRAN_SMTP_ITEMSIZE	10	/* bytes */
#define GRAN_NUMITEMS		1	/* items */
#define GRAN_NUMCONNS		1	/* items */
#define GRAN_MAXCONNS		1	/* items */


/* for debugging */

/* #undef GRAN_BURSTSIZE		 */
/* #define GRAN_BURSTSIZE		1 */
