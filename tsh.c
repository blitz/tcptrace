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

#include "tcptrace.h"

#ifdef GROK_TSH

/* Defining SYS_STDIN which is fp for Windows and stdin for all other systems */
#ifdef __WIN32
static FILE *fp;
#define SYS_STDIN fp
#else
#define SYS_STDIN stdin
#endif /* __WIN32 */

/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;
static struct ip *ipb;
static struct tcphdr *tcpb;

/* for debugging */

#define TSH_PLEN 44

/* return the next packet header */
static int
pread_tsh(
  struct timeval *ptime,
  int *plen,
  int *ptlen,
  void **pphys,
  int *pphystype,
  struct ip **ppip,
  void **pplast)
{
  unsigned char inbuf[TSH_PLEN];
  int rlen;
  

  while (1) {
    /* read the packet info */
    rlen = fread(inbuf, sizeof(unsigned char), TSH_PLEN, SYS_STDIN);

    /* if we reach the End Of File we stop */
    if (rlen == EOF) {
      return(0);
    }
    /* if we can't read all 40 bytes, we give up on the file */
    if (rlen != TSH_PLEN) {
      fprintf(stderr,"Bad tsh packet header, only [%d] bytes where 40 byte records required \n", rlen);
      return(0);
    }

    ipb->ip_src.s_addr = *(int *)&(inbuf[20]);
    ipb->ip_dst.s_addr = *(int *)&(inbuf[24]);
    ipb->ip_hl = inbuf[8] & 0x0F;
    ipb->ip_v = inbuf[8]>>4;
	
    ipb->ip_tos = inbuf[9];
    ipb->ip_off = inbuf[14]<<8 + inbuf[15];
    ipb->ip_ttl = inbuf[16];
    ipb->ip_p = 6;
    ipb->ip_sum = inbuf[18]<<8 + inbuf[19]; 
    ipb->ip_id = inbuf[12]<<8 + inbuf[13];
    *plen = sizeof(struct ip) + *(short *)&(inbuf[10]);
    ipb->ip_len = htons(*plen);

    if (inbuf[17] == IPPROTO_TCP) {
      tcpb->th_sport = *(short *)&(inbuf[28]);
      tcpb->th_dport = *(short *)&(inbuf[30]);

      tcpb->th_seq = *(int *)&(inbuf[32]); 
      tcpb->th_ack = *(int *)&(inbuf[36]);

      tcpb->th_off = inbuf[40]>>2;
      tcpb->th_x2 = 0;

      tcpb->th_flags = inbuf[37];
      tcpb->th_sum = 0;
      tcpb->th_urp = 0;
      tcpb->th_win = inbuf[38]<<8 + inbuf[39];
    }

    ptime->tv_sec  = inbuf[0]<<24 + inbuf[1]<<16 + inbuf[2]<<8 + inbuf[3];
    ptime->tv_usec = inbuf[5]<<16 + inbuf[6]<<8 + inbuf[7];

    *ptlen = *plen;

    *ppip  = (struct ip *) pip_buf;
    *pplast = (char *)pip_buf + *plen;
    *pphys  = pep;
    *pphystype = PHYS_ETHER;

    return(1);
  }
}

pread_f *is_tsh(char *filename)
{
  int rlen;
  unsigned char inbuf[TSH_PLEN];

#ifdef __WIN32
  if((fp = fopen(filename, "r")) == NULL) {
    perror(filename);
    exit(-1);
  }
#endif /* __WIN32 */   

  rlen = fread(inbuf, sizeof(unsigned char), TSH_PLEN, SYS_STDIN);
  rewind(SYS_STDIN);

  /* this is *really* cheap, but assume it's a tsh trace if the 9th
     byte is standard IPv4 0x0405 */
  if (rlen == TSH_PLEN) {
    if (inbuf[8] != 0x45) return(NULL);
  } else { return(NULL); }

  /* OK, it's mine.  Init some stuff */
  pep = MallocZ(sizeof(struct ether_header));
  pip_buf = MallocZ(IP_MAXPACKET);
    
  ipb = (struct ip *) pip_buf;
  tcpb = (struct tcphdr *) (ipb + 1);

  /* Set up the stuff that shouldn't change */
  pep->ether_type = ETHERTYPE_IP;

  return(pread_tsh); 
}
#endif /* GROK_TSH */
