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
static char const copyright[] =
    "@(#)Copyright (c) 1996\nOhio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


#define NETM_DUMP_OFFSET 0x1000



/* netm file header format */
struct netm_header {
	int	netm_key;
	int	version;
};
#define VERSION_OLD 3
#define VERSION_NEW 4
#define NETM_KEY 0x6476


/* netm packet header format */
struct packet_header_old {
	int	unused1;
	int	unused2;
	int	tstamp_secs;
	int	tstamp_usecs;
	int	unused3;
	int	len;
};
struct packet_header {
	int	unused1;
	int	tstamp_secs;
	int	tstamp_usecs;
	int	unused2;
	int	unused3;
	int	len;
	int	tlen;  /* truncated length */
	int	unused5;
};
