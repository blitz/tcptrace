/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998
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

#ifndef HAVE_LONG_LONG
#define V_ULLONG V_ULONG
#define V_LLONG V_LONG
#endif /* HAVE_LONG_LONG */



/* just a big table of things that we can filter on */
static tcp_pair ptp_dummy;
#define PTCB_C_S(field) &ptp_dummy.a2b.field,&ptp_dummy.b2a.field
struct filter_line filters[] = {
    {"hostname",	V_STRING,&ptp_dummy.a_hostname,&ptp_dummy.b_hostname},
    {"portname",	V_STRING,&ptp_dummy.a_portname,&ptp_dummy.b_portname},
    {"port",		V_USHORT,&ptp_dummy.addr_pair.a_port,&ptp_dummy.addr_pair.b_port},

    {"f1323_ws",	V_BOOL,	PTCB_C_S(f1323_ws)},
    {"f1323_ts",	V_BOOL,	PTCB_C_S(f1323_ts)},
    {"fsack_req",	V_BOOL,	PTCB_C_S(fsack_req)},
    {"window_scale",	V_BOOL,	PTCB_C_S(window_scale)},

    {"data_bytes",	V_ULLONG,	PTCB_C_S(data_bytes)},
    {"data_pkts",	V_ULLONG,	PTCB_C_S(data_pkts)},
    {"data_pkts_push",	V_ULLONG,	PTCB_C_S(data_pkts_push)},
    {"rexmit_bytes",	V_ULLONG,	PTCB_C_S(rexmit_bytes)},
    {"rexmit_pkts",	V_ULLONG,	PTCB_C_S(rexmit_pkts)},
    {"ack_pkts",	V_ULLONG,	PTCB_C_S(ack_pkts)},
    {"win_max",		V_ULONG,	PTCB_C_S(win_max)},
    {"win_min",		V_ULONG,	PTCB_C_S(win_min)},
    {"win_tot",		V_ULONG,	PTCB_C_S(win_tot)},
    {"win_zero_ct",	V_ULONG,	PTCB_C_S(win_zero_ct)},
    {"min_seq",		V_ULONG,	PTCB_C_S(min_seq)},
    {"max_seq",		V_ULONG,	PTCB_C_S(max_seq)},
    {"packets",		V_ULLONG,	PTCB_C_S(packets)},
    {"syn_count",	V_UCHAR,	PTCB_C_S(syn_count)},
    {"fin_count",	V_UCHAR,	PTCB_C_S(fin_count)},
    {"reset_count",	V_UCHAR,	PTCB_C_S(reset_count)},
    {"min_seg_size",	V_ULONG,	PTCB_C_S(min_seg_size)},
    {"max_seg_size",	V_ULONG,	PTCB_C_S(max_seg_size)},
    {"out_order_pkts",	V_ULLONG,	PTCB_C_S(out_order_pkts)},
    {"sacks_sent",	V_ULLONG,	PTCB_C_S(sacks_sent)},
    {"ipv6_segments",	V_ULONG,	PTCB_C_S(ipv6_segments)},
};
#define NUM_FILTERS (sizeof(filters)/sizeof(struct filter_line))
