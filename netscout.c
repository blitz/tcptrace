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
static char const copyright[] =
    "@(#)Copyright (c) 2001 -- Ohio University.\n";
static char const rcsid[] =
    "@(#)$Header$";


/* 
 * netscout.c - NetScout 5.5.1 Ascii file decode 
 * 
 * This file submitted by Al.Broscius@msdw.com
 *
 */


#include "tcptrace.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef GROK_NETSCOUT

#ifdef linux
#ifdef strncpy
 /* problem with macro won't let this file compile */
#undef strncpy
#endif /* strncpy */
#endif /* linux */

/* Defining SYS_STDIN which is fp for Windows and stdin for all other systems */
#ifdef __WIN32
static FILE *fp;
#define SYS_STDIN fp
#else
#define SYS_STDIN stdin
#endif /* __WIN32 */

/* static buffers for reading */
static int *pep_buf;
static int *pip_buf;



/*  file header format */
struct netscout_header {
  tt_int32 pagenum;
  char filename[255];
};


/* netm packet header format */
struct netscout_packet_header {
    tt_int32	FrameNum;
    tt_int32	Size;
    tt_int32	tstamp_secs;
    tt_int32	tstamp_msecs;
    tt_int32	tlen;
    tt_int32	len;
};


/* currently only works for ETHERNET */
static int
pread_netscout(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
  char * retval;
  char buffer_string[256];
  char month[256];
  int day, hour, minute, sec, msec;
  struct tm tmval;
  int byte0, byte1, byte2,byte3,byte4,byte5,byte6,byte7,
    byte8,byte9,byte10,byte11,byte12,byte13,byte14,byte15;
  int index;

  /* Look for Frame line to signal start of packet */

  if((retval = fgets (buffer_string, 255, SYS_STDIN)) == NULL) {
    return 0;
  }
  while(strstr(buffer_string, "Frame") == NULL) {
    if((retval = fgets (buffer_string, 255, SYS_STDIN)) == NULL) {
      return 0;
    }
  }

  /* recover the size of the captured packet header */
  sscanf(strlen("Size") + strstr(buffer_string, "Size"), "%d", ptlen);

  *plen = 62;
  *pplast = (char *) pip_buf+48;

  /* recover the timestamp */
  sscanf(strlen("Time") + strstr(buffer_string, "Time"), "%s %d %d:%d:%d.%d", 
	 month, &day, &hour, &minute, &sec, &msec);
  tmval.tm_sec = sec;
  tmval.tm_min = minute;
  tmval.tm_hour = hour;
  tmval.tm_mday = day;
  tmval.tm_mon = 
    (strlen(strstr("DecNovOctSepAugJulJunMayAprMarFebJan", month)) / 3) - 1;
  tmval.tm_year = 1999-1900;
  tmval.tm_isdst = -1;
  ptime->tv_sec = mktime(&tmval);
  ptime->tv_usec = msec * 1000;

  /* Claim that the packets came from an Ethernet */
  *pphystype = PHYS_ETHER;

  /* Look for 00000: line to signal first row of packet data */
  if((retval = fgets (buffer_string, 255, SYS_STDIN)) == NULL) {
    return 0;
  }
  while(strstr(buffer_string, "00000:") == NULL) {
    if((retval = fgets (buffer_string, 255, SYS_STDIN)) == NULL) {
      return 0;
    }
  }

  index = 0;
  sscanf(strstr(buffer_string,":") + 1, 
	 "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x", 
	 &byte0, &byte1, &byte2,&byte3,&byte4,&byte5,&byte6,&byte7,
	 &byte8,&byte9,&byte10,&byte11,&byte12,&byte13,&byte14,&byte15);
  pep_buf[index++] =ntohl(byte0<<24|byte1<<16|byte2<<8|byte3);
  pep_buf[index++] =ntohl(byte4<<24|byte5<<16|byte6<<8|byte7);
  pep_buf[index++] =ntohl(byte8<<24|byte9<<16|byte10<<8|byte11);
  pep_buf[index++] =ntohl(byte12<<24|byte13<<16|byte14<<8|byte15);

  /* Look for 00016: line to signal first row of packet data */
  if((retval = fgets (buffer_string, 255, SYS_STDIN)) == NULL) {
    return 0;
  }
  while(strstr(buffer_string, "00016:") == NULL) {
    if((retval = fgets (buffer_string, 255, SYS_STDIN)) == NULL) {
      return 0;
    }
  }

  sscanf(strstr(buffer_string,":") + 1, 
	 "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x", 
	 &byte0, &byte1, &byte2,&byte3,&byte4,&byte5,&byte6,&byte7,
	 &byte8,&byte9,&byte10,&byte11,&byte12,&byte13,&byte14,&byte15);
  pep_buf[index++] =ntohl(byte0<<24|byte1<<16|byte2<<8|byte3);
  pep_buf[index++] =ntohl(byte4<<24|byte5<<16|byte6<<8|byte7);
  pep_buf[index++] =ntohl(byte8<<24|byte9<<16|byte10<<8|byte11);
  pep_buf[index++] =ntohl(byte12<<24|byte13<<16|byte14<<8|byte15);

  /* Look for 00032: line to signal first row of packet data */
  if((retval = fgets (buffer_string, 255, SYS_STDIN)) == NULL) {
    return 0;
  }
  while(strstr(buffer_string, "00032:") == NULL) {
    if((retval = fgets (buffer_string, 255, SYS_STDIN)) == NULL) {
      return 0;
    }

  }

  sscanf(strstr(buffer_string,":") + 1, 
	 "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x", 
	 &byte0, &byte1, &byte2,&byte3,&byte4,&byte5,&byte6,&byte7,
	 &byte8,&byte9,&byte10,&byte11,&byte12,&byte13,&byte14,&byte15);
  pep_buf[index++] =ntohl(byte0<<24|byte1<<16|byte2<<8|byte3);
  pep_buf[index++] =ntohl(byte4<<24|byte5<<16|byte6<<8|byte7);
  pep_buf[index++] =ntohl(byte8<<24|byte9<<16|byte10<<8|byte11);
  pep_buf[index++] =ntohl(byte12<<24|byte13<<16|byte14<<8|byte15);
  
  
  memcpy((char *) pip_buf, (char *) pep_buf + 14, 48);

  *ppip = (struct ip *) pip_buf;
  return 1;
}



/* is the input file a NetScout format file?? */
pread_f *is_netscout(char *filename)
{    
   struct netscout_header nhdr;
   char * retval;
   char buffer_string[256];

#ifdef __WIN32
    if((fp = fopen(filename, "r")) == NULL) {
       perror(filename);
       exit(-1);
    }
#endif /* __WIN32 */   
   
   /* read the netscout file header */
   retval =  fgets (buffer_string, 255, SYS_STDIN);
   if(strstr(buffer_string, "Page" ) != NULL) {
     retval =  fgets (buffer_string, 255, SYS_STDIN);
     if(strstr(buffer_string, "Protocol Decode Output") != NULL) {
       fflush(stdout);
       retval =  fgets (buffer_string, 255, SYS_STDIN);
       if(strstr(buffer_string, "Packets from the file:") != NULL) {
	 strncpy((char *) &(nhdr.filename[0]), buffer_string, 
		 strlen("Packets from the file:")); 
       }
     }
   }
   else 
     {
       rewind(SYS_STDIN);
       return(NULL);
     }
   
   /* OK, it's mine.  Init some stuff */
   pep_buf = MallocZ(IP_MAXPACKET);
   pip_buf = MallocZ(IP_MAXPACKET);

   return(pread_netscout);

}

#endif /* GROK_NETSCOUT */
