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
 * Author:	Eric Helvey
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ehelvey@cs.ohiou.edu
 */
static char const rcsid_tcplib[] =
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
#define TCPLIBPORT_SMTP 0
#define TCPLIBPORT_NNTP 1
#define TCPLIBPORT_TELNET 2
#define TCPLIBPORT_FTP 3
#define TCPLIBPORT_HTTP 4
#define TCPLIBPORT_NONE -1


#define MAX_TEL_INTER_COUNT 1500000
#define TIMER_VAL  60
#define NUM_APPS 5
#define BREAKDOWN_HASH 1000000


/* data file names */
#define DEFAULT_TCPLIB_DATADIR		"data"
#define TCPLIB_TELNET_DURATION_FILE	"telnet.duration"
#define TCPLIB_TELNET_PACKETSIZE_FILE	"telnet.pktsize"
#define TCPLIB_TELNET_INTERARRIVAL_FILE	"telnet.interarrival"
#define TCPLIB_FTP_ITEMSIZE_FILE	"ftp.itemsize"
#define TCPLIB_FTP_CTRLSIZE_FILE	"ftp.ctlsize"
#define TCPLIB_SMTP_ITEMSIZE_FILE	"smtp.itemsize"
#define TCPLIB_NNTP_ITEMSIZE_FILE	"nntp.itemsize"
#define TCPLIB_HTTP_ITEMSIZE_FILE	"http.itemsize"
#define TCPLIB_BREAKDOWN_FILE		"breakdown"
#define TCPLIB_BREAKDOWN_GRAPH_FILE	"breakdown_hist"
#define TCPLIB_NEXT_CONVERSE_FILE	"conv.conv_time"
#define TCPLIB_CONV_DURATION_FILE	"conv.duration"
