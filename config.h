/*
 * Copyright (c) 1994, 1995, 1996
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
static char const rcsid_config[] =
    "@(#)$Header$";


/* define GROK_SNOOP if you want tcptrace to understand the output
   format of Sun's "snoop" packet sniffer. */
#define GROK_SNOOP


/* define GROK_TCPDUMP if you want tcptrace to understand the output
   format format of the LBL tcpdump program (actually, the pcap
   libraries, which you'll need but are not included here) */
#define GROK_TCPDUMP


/* define GROK_NETM if you want tcptrace to understand the output
   format of HP's "netm" monitoring system's packet sniffer. */
#define GROK_NETM


/* define GROK_ETHERPEEK if you want tcptrace to understand the output
   format of the Macintosh program Etherpeek */
#define GROK_ETHERPEEK
