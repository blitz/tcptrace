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
 * Author:	Marina Bykova
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 */
static char const rcsid_realtime[] =
    "@(#)$Header$";

/* header file for mod_realtime.c */
int realtime_init(int argc, char *argv[]);
void realtime_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmod_data);
void realtime_done(void);
void realtime_usage(void);
void realtime_udp_read(struct ip *pip, udp_pair *pup, void *plast, void *pmodstruct);
void realtime_nontcpudp_read(struct ip *pip, void *plast);
void *realtime_newconn( tcp_pair *ptp);
void realtime_deleteconn(tcp_pair *ptp, void *mod_data);

