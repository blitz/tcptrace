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
static char const copyright[] =
    "@(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


#include "tcptrace.h"

static long tcp_pair_pool = -1;
static long seqspace_pool = -1;
static long ptp_snap_pool = -1;
static long ptp_ptr_pool  = -1;
static long segment_pool  = -1;
static long quadrant_pool = -1;

tcp_pair *
MakeTcpPair(
	    void)
{
  tcp_pair	*ptr = NULL;

  if (tcp_pair_pool < 0) {
    tcp_pair_pool = MakeMemPool(sizeof(tcp_pair), 0);
  }
  
  ptr = PoolMalloc(tcp_pair_pool, sizeof(tcp_pair));
  return ptr;
}

void
FreeTcpPair(
	    tcp_pair *ptr)
{
  PoolFree(tcp_pair_pool, ptr);
}

seqspace *
MakeSeqspace(
	     void)
{
  seqspace	*ptr = NULL;

  if (seqspace_pool < 0) {
    seqspace_pool = MakeMemPool(sizeof(seqspace), 0);
  }
  
  ptr = PoolMalloc(seqspace_pool, sizeof(seqspace));
  return ptr;
}

void
FreeSeqspace(
	     seqspace *ptr)
{
  PoolFree(seqspace_pool, ptr);
}

ptp_snap *
MakePtpSnap(
	    void)
{
  ptp_snap	*ptr = NULL;

  if (ptp_snap_pool < 0) {
    ptp_snap_pool = MakeMemPool(sizeof(ptp_snap), 0);
  }
  
  ptr = PoolMalloc(ptp_snap_pool, sizeof(ptp_snap));
  return ptr;
}

void
FreePtpSnap(
	    ptp_snap *ptr)
{
  PoolFree(ptp_snap_pool, ptr);
}

ptp_ptr *
MakePtpPtr(
	   void)
{
  ptp_ptr	*ptr = NULL;

  if (ptp_ptr_pool < 0) {
    ptp_ptr_pool = MakeMemPool(sizeof(ptp_ptr), 0);
  }
  
  ptr = PoolMalloc(ptp_ptr_pool, sizeof(ptp_ptr));
  return ptr;
}

void
FreePtpPtr(
	   ptp_ptr *ptr)
{
  PoolFree(ptp_ptr_pool, ptr);
}

segment *
MakeSegment(
	    void)
{
  segment	*ptr = NULL;

  if (segment_pool < 0) {
    segment_pool = MakeMemPool(sizeof(segment), 0);
  }
  
  ptr = PoolMalloc(segment_pool, sizeof(segment));
  return ptr;
}

void
FreeSegment(
	    segment *ptr)
{
  PoolFree(segment_pool, ptr);
}

quadrant *
MakeQuadrant(
	     void)
{
  quadrant	*ptr = NULL;

  if (quadrant_pool < 0) {
    quadrant_pool = MakeMemPool(sizeof(quadrant), 0);
  }
  
  ptr = PoolMalloc(quadrant_pool, sizeof(quadrant));
  return ptr;
}

void
FreeQuadrant(
	     quadrant *ptr)
{
  PoolFree(quadrant_pool, ptr);
}
