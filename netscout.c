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
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 */
static char const copyright[] =
    "@(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
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

/* static buffers for reading */
static int *pep_buf;
static int *pip_buf;



/*  file header format */
struct netscout_header {
  int pagenum;
  char filename[255];
};


/* netm packet header format */
struct netscout_packet_header {
    int	FrameNum;
    int	Size;
    int	tstamp_secs;
    int	tstamp_msecs;
    int	tlen;
    int	len;
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

  if((retval = fgets (buffer_string, 255, stdin)) == NULL) {
    return 0;
  }
  while(strstr(buffer_string, "Frame") == NULL) {
    if((retval = fgets (buffer_string, 255, stdin)) == NULL) {
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
  if((retval = fgets (buffer_string, 255, stdin)) == NULL) {
    return 0;
  }
  while(strstr(buffer_string, "00000:") == NULL) {
    if((retval = fgets (buffer_string, 255, stdin)) == NULL) {
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
  if((retval = fgets (buffer_string, 255, stdin)) == NULL) {
    return 0;
  }
  while(strstr(buffer_string, "00016:") == NULL) {
    if((retval = fgets (buffer_string, 255, stdin)) == NULL) {
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
  if((retval = fgets (buffer_string, 255, stdin)) == NULL) {
    return 0;
  }
  while(strstr(buffer_string, "00032:") == NULL) {
    if((retval = fgets (buffer_string, 255, stdin)) == NULL) {
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
pread_f *is_netscout(void)
{    
   struct netscout_header nhdr;
   char * retval;
   char buffer_string[256];

   /* read the netscout file header */
   retval =  fgets (buffer_string, 255, stdin);
   if(strstr(buffer_string, "Page" ) != NULL) {
     retval =  fgets (buffer_string, 255, stdin);
     if(strstr(buffer_string, "Protocol Decode Output") != NULL) {
       fflush(stdout);
       retval =  fgets (buffer_string, 255, stdin);
       if(strstr(buffer_string, "Packets from the file:") != NULL) {
	 strncpy((char *) &(nhdr.filename[0]), buffer_string, 
		 strlen("Packets from the file:")); 
       }
     }
   }
   else 
     {
       rewind(stdin);
       return(NULL);
     }
   
   /* OK, it's mine.  Init some stuff */
   pep_buf = MallocZ(IP_MAXPACKET);
   pip_buf = MallocZ(IP_MAXPACKET);

   return(pread_netscout);

}

#endif /* GROK_NETSCOUT */
