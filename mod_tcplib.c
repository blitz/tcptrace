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
static char const rcsid_tcplib[] =
   "$Id$";

#ifdef LOAD_MODULE_TCPLIB

/* ***************************************************************************
 * 
 * Module Title: Mod_TCPLib 
 * 
 * Author: Eric Helvey
 * 
 * Purpose: To generate data files needed by TCPLib and TrafGen.
 * 
 * ***************************************************************************/
#include "tcptrace.h"
#include "mod_tcplib.h"


/* Function Prototypes */
static int is_telnet_port(int port);
static void tcplib_do_telnet_duration();
static void tcplib_add_telnet_interarrival(tcp_pair *ptp, struct timeval *ptp_saved);
static void tcplib_do_telnet_packetsize();
static void tcplib_add_telnet_packetsize(int length);
static void tcplib_do_telnet();
static int is_ftp_data_port(int port);
static int is_ftp_control_port(int port);
static void tcplib_do_ftp_itemsize();
static void tcplib_do_ftp_num_items();
static void tcplib_do_ftp_control_size();
static void tcplib_do_ftp();
static int is_smtp_port(int port);
static void tcplib_do_smtp();
static int is_nntp_port(int port);
static void tcplib_do_nntp_itemsize();
static void tcplib_do_nntp_numitems();
static void tcplib_do_nntp();
static int is_http_port(int port);
static void tcplib_do_http_itemsize();
static void tcplib_do_http();
static void tcplib_do_telnet_interarrival();
static void update_breakdown(tcp_pair *ptp);
static int breakdown_type(int port);
static void do_final_breakdown(char* filename);
static void setup_breakdown();
static void tcplib_init_setup();
static void do_tcplib_next_converse(tcp_pair *ptp);
static void do_tcplib_final_converse();
static struct tcplib_next_converse * file_extract(FILE* fil, int *lines, int *count);
char * namedfile(char * file);



/* External global varialbes */
extern tcp_pair **ttp;
extern int num_tcp_pairs;


/* Local global variables */
static int tcplib_telnet_packetsize_count[MAX_TEL_PACK_SIZE_COUNT];
static int tcplib_telnet_interarrival_count[MAX_TEL_INTER_COUNT];
static int tcplib_breakdown_total[5];
static int tcplib_breakdown_interval[5];
static timeval last_interval;
static int interval_count;
static char breakdown_hash_char[] = { 'S', 'N', 'T', 'F', 'H' };
static FILE* hist_file;
static int this_file = 0;
static struct tcplib_next_converse *next_converse_breakdown = NULL;
static int size_next_converse_breakdown = 0;
static timeval last_converse;
static int ipport_offset = IPPORT_OFFSET;
static char *current_file = NULL;
static char output_dir[128] = "";


/* First section is comprised of functions that TCPTrace will call
 * for all modules.
 */

/* **************************************************************************
 * 
 * Function Name: tcplib_init
 * 
 * Returns:  TRUE/FALSE whether or not the tcplib module for tcptrace
 *           has been requested on the command line.
 *
 * Purpose: To parse the command line arguments for the tcplib module's
 *          command line flags, return whether or not to run the module,
 *          and to set up the local global variables needed to generate
 *          the tcplib data files.
 *
 * Called by: LoadModules() in tcptrace.c
 * 
 * 
 * ***************************************************************************/
int tcplib_init(
    int argc,      /* Number of command line arguments */
    char *argv[]   /* Command line arguments */
    )
{
    int i;             /* Runner for command line arguments */
    int enable = 0;    /* Do we turn on this module, or not? */
    int dirlen = 0;    /* Length of the user specified directory name */

    for(i = 0; i < argc; i++) {

	if(!argv[i])
	    continue;

	/* The "-F" flag currently triggers the tcplib module */
	if(argv[i] && !strncmp(argv[i], "-x", 2)) {
	    if(!strncasecmp(argv[i]+2, "tcplib", sizeof("tcplib")-1)) {
		/* Calling the Tcplib part */
		enable = 1;

		printf("Capturing TCPLib traffic\n");

 	        /* We free this argument so that no other modules
	         * or the main program mis-interprets this flag.
	         */
		argv[i] = NULL;

		continue;
	    }
	}

	/* The "-J ####" flag sets the offset that we're going
	 * to consider for tcplib data files.  The reason is that
	 * for verification purposes, when trafgen creates traffic 
	 * it sends it to non-standard ports.  So, in order to get
	 * a data set from generated traffic, we'd have to remove
	 * the offset.  The -J allows us to do that.
	 */
	if(argv[i] && !strncmp(argv[i], "-J", 2)) {

	    if(i >= argc-1) {
		printf("Flag \"-J\" must have an integer argument.\n");
		exit(1);
	    }

	    ipport_offset = atoi(argv[i+1]);

	    if(!ipport_offset) {
		printf("Invalid argument to flag \"-J\".  Must be integer value greater than 0.\n");
		exit(1);
	    }

	    printf("TCPLib port offset - %d\n", ipport_offset);

	    argv[i+1] = NULL;
	    argv[i] = NULL;

	    continue;
	}


	/* We will probably need to add another flag here to
	 * specify the directory in which to place the data
	 * files.  And here it is.
	 */
	if(argv[i] && !strncmp(argv[i], "-O", 2)) {

	    if(i >= argc-1) {
		printf("Flag \"-O\" must have a string argument.\n");
		exit(1);
	    }

	    if(output_dir[0]) {
		*output_dir = '\00';
	    }

	    dirlen = strlen(argv[i+1]);

	    if(argv[i+1][dirlen - 1] == '/')
		argv[i+1][dirlen - 1] = '\0';

	    if(dirlen >= 127) {
		printf("Output directory too long. Exiting.\n");
		exit(1);
	    }

	    sprintf(output_dir, "%s/", argv[i+1]);

	    printf("TCPLib output directory - %sdata\n", output_dir);

	    argv[i+1] = NULL;
	    argv[i] = NULL;

	    continue;
	}

    }

    /* If enable is not true, then all tcplib functions will
     * be ignored during this run of the program.
     */
    if(!enable)
	return FALSE;
    else {
	tcplib_init_setup();
	return TRUE;
    }
}







/* **************************************************************************
 * 
 * Function Name: tcplib_done
 * 
 * Returns: Nothing
 *
 * Purpose: This function runs after all the packets have been read in
 *          and filed.  The functions that tcplib_done calls are the ones
 *          that generate the data files.
 *
 * Called by: FinishModules() in tcptrace.c
 * 
 * 
 * ***************************************************************************/
void tcplib_done()
{
    /* Here's where I need to take the data that I've got
     * and break it down and print it out
     */
    tcplib_do_telnet();
    tcplib_do_ftp();
    tcplib_do_smtp();
    tcplib_do_nntp();
    tcplib_do_http();
    do_final_breakdown(current_file);
    do_tcplib_final_converse();

    return;
}








/* **************************************************************************
 * 
 * Function Name: tcplib_read
 * 
 * Returns: Nothing
 *
 * Purpose: This function is called each time a packet is read in by
 *          tcptrace.  tcplib_read examines the packet, and keeps track
 *          of certain information about the packet based on the packet's
 *          source and/or destination ports.
 *
 * Called by: ModulesPerPacket() in tcptrace.c
 * 
 * 
 * ***************************************************************************/
void tcplib_read(
    struct ip *pip,    /* The packet */
    tcp_pair *ptp,     /* The pair of hosts - basically the conversation */
    void *plast,       /* Unused here */
    void *pmodstruct   /* Nebulous structure used to hold data that the module
			* feels is important.  In this case, we store the time
			* of the last packet in the conversation to arrive. */
    )
{
    struct tcphdr *tcp;  /* TCP header information */
    int data_len = 0;    /* Length of the data cargo in the packet, and
			  * the period of time between the last two packets
			  * in a conversation */
    int a2b_len;         /* The type of traffic associated with a's port # */
    int b2a_len;         /* The type of traffic associated with b's port # */
    

    /* Setting a pointer to the beginning of the TCP header */
    tcp = (struct tcphdr *) ((char *)pip + (sizeof(int) * pip->ip_hl));

    /* Let's do the telnet packet sizes.  Telnet packets are the only
     * ones where we actually care about the sizes of individual packets.
     * All the other connection types are a "send as fast as possible" 
     * kind of setup where the packet sizes are always optimal.  Because
     * of this, we need the size of each and every telnet packet that 
     * comes our way. */
    if(   is_telnet_port(ptp->addr_pair.a_port)
       || is_telnet_port(ptp->addr_pair.b_port)) {
	data_len = pip->ip_len - 
	           (sizeof(int) * pip->ip_hl) - 
	           (sizeof(int) * tcp->th_off);

	tcplib_add_telnet_packetsize(data_len);
    }

    /* Here's where we'd need to do telnet interarrival times.  The
     * same basic scenario applies with telnet packet interarrival
     * times.  Because telnet type traffic is "stop and go", we need
     * to be able to model how long the "stops" are.  So we measure
     * the time in between successive packets in a single telnet
     * conversation. */
    tcplib_add_telnet_interarrival(ptp, (struct timeval *)pmodstruct);

    if((a2b_len = breakdown_type(ptp->addr_pair.a_port)) != -1)
	tcplib_breakdown_interval[a2b_len] += ptp->a2b.data_bytes;

    if((b2a_len = breakdown_type(ptp->addr_pair.b_port)) != -1)
	tcplib_breakdown_interval[b2a_len] += ptp->b2a.data_bytes;

    /* This is just a sanity check to make sure that we've got at least
     * one time, and that our breakdown section is working on the same
     * file that we are. */
    data_len = (ptp->last_time.tv_sec - last_interval.tv_sec);
    
    if(data_len >= TIMER_VAL) {
	update_breakdown(ptp);
    }

    return;
}







/* **************************************************************************
 * 
 * Function Name: tcplib_newconn
 * 
 * Returns: The time of this connection.  This becomes the pmodstruct that
 *          is returned with each call to tcplib_read.
 *
 * Purpose: To setup and handle new connections.
 *
 * Called by: ModulesPerConn() in tcptrace.c
 * 
 * 
 * ***************************************************************************/
void * tcplib_newconn(
    tcp_pair *ptp   /* This conversation */
    )
{
    struct timeval *pmodstruct;   /* Pointer to a timeval structure.  The
				   * timeval structure becomes the time of
				   * the last connection.  The pmodstruct
				   * is tcptrace's way of allowing modules
				   * to keep track of information about
				   * connections */

    do_tcplib_next_converse(ptp);

    pmodstruct = (struct timeval *)malloc(sizeof(struct timeval));

    return (void *)pmodstruct;
}






/* **************************************************************************
 * 
 * Function Name: tcplib_newfile
 * 
 * Returns: Nothing
 *
 * Purpose: This function is called by tcptrace every time that a new
 *          trace file is opened.  tcplib_newfile basically sets up a new
 *          line in the breakdown file, so that we can get a picture of
 *          the traffic distribution for a single trace.
 *
 * Called by: ModulesPerFile() in tcptrace.c
 * 
 * 
 * ***************************************************************************/
void tcplib_newfile(
    char *filename,     /* Name of the file just opened. */
    u_long filesize,
    Bool fcompressed
    )
{

    /* If this isn't the first file that we've seen this run, then
     * we want to run do_final_breakdown on the file we ran BEFORE
     * this one. */
    if(this_file) {
	do_final_breakdown(current_file);
	free(current_file);
	current_file = (char *) strdup(filename);
	
    } else {
	/* If this is the first file we've seen, then we just want to 
	 * record the name of this file, and do nothing until the file
	 * is done. */
	printf("%s", filename);

	current_file = (char *) strdup(filename);

    }	

    setup_breakdown();
    this_file = TRUE;

    return;
}







/* **************************************************************************
 * 
 * Function Name: tcplib_usage
 * 
 * Returns: Nothing
 *
 * Purpose: To print out usage instructions for this module.
 *
 * Called by: ListModules() in tcptrace.c
 * 
 * 
 * ***************************************************************************/
void tcplib_usage()
{
    printf("\t-xtcplib\tgenerate tcplib-format data files from packets\n");
}

/* End of the tcptrace standard function section */








/* **************************************************************************
 * 
 * Function Name: tcplib_init_setup
 * 
 * Returns: Nothing
 *
 * Purpose:  To setup and initialize the tcplib module's set of 
 *           global variables.
 *
 * Called by: tcplib_init() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
static void tcplib_init_setup()
{
    int i;   /* Loop Counter */

    /* We need to save the contents in order to piece together the answers
     * later on
     */
    save_tcp_data = FALSE;

    for(i = 0; i < MAX_TEL_PACK_SIZE_COUNT; i++)
	tcplib_telnet_packetsize_count[i] = 0;

    for(i = 0; i < MAX_TEL_INTER_COUNT; i++)
	tcplib_telnet_interarrival_count[i] = 0;

    for(i = 0; i < NUM_APPS; i++){
	tcplib_breakdown_total[i] = 0;
	tcplib_breakdown_interval[i] = 0;
    }

    setup_breakdown();

    last_interval.tv_sec = 0;
    last_interval.tv_usec = 0;
    last_converse.tv_sec = 0;
    last_converse.tv_usec = 0;

    return;
}









/* **************************************************************************
 * 
 * Function Name: setup_breakdown
 * 
 * Returns: Nothing
 *
 * Purpose: To open the traffic breakdown graph file, and to set the
 *          interval count.
 *
 * Called by: tcplib_init_setup() in mod_tcplib.c
 *            tcplib_newfile()    in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
static void setup_breakdown()
{
    if(!(hist_file = fopen(namedfile(TCPLIB_BREAKDOWN_GRAPH_FILE), "w"))) {
	printf("Error opening breakdown histogram file - %s.\n", 
	       namedfile(TCPLIB_BREAKDOWN_GRAPH_FILE));
	exit(1);
    }

    interval_count = 0;
}







/* **************************************************************************
 * 
 * Function Name: update_breakdown
 * 
 * Returns: Nothing
 *
 * Purpose: To create a file containing a kind of histogram of traffic
 *          seen in this file.  The histogram would contain one row per
 *          a set # of seconds, and would display one characteristic
 *          character per a specified number of bytes.
 *
 * Called by: tcplib_read() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
static void update_breakdown(
    tcp_pair *ptp      /* This conversation */
    )
{
    int i;        /* Looping variable */
    int count;
    
    /* Displays the interval number.  A new histogram line is displayed
     * at TIMER_VALUE seconds. */
    fprintf(hist_file, "%d\t", interval_count);

    /* Display some characters for each type of traffic */
    for(i = 0; i < NUM_APPS; i++) {

	/* We'll be displaying one character per BREAKDOWN_HASH number of bytes */
	count = (tcplib_breakdown_interval[i] / BREAKDOWN_HASH) + 1;

	/* If there was actually NO traffic of that type, then we don't
	 * want to display any characters.  But if there was a little bit
	 * of traffic, even much less than BREAKDOWN_HASH, we want to 
	 * acknowledge it. */
	if(!tcplib_breakdown_interval[i])
	    count--;

	/* Print one hash char per count. */
	while(count > 0) {
	    fprintf(hist_file, "%c", breakdown_hash_char[i]);
	    count--;
	}
    }

    /* After we've done all the applications, end the line */
    fprintf(hist_file, "\n");

    /* Move the data for this breakdown interval into the total breakdown
     * data area.  We'll be using this stuff at the end, so we need to
     * keep track of it now. */
    for(i = 0; i < NUM_APPS; i++) {
	tcplib_breakdown_total[i]+= tcplib_breakdown_interval[i]/1000;
	tcplib_breakdown_interval[i] = 0;
    }

    /* Update the breakdown interval */
    interval_count++;

    /* Update the time that the last breakdown interval occurred. */
    last_interval.tv_sec = ptp->last_time.tv_sec;
}



/* **************************************************************************
 * 
 * Function Name: namedfile
 * 
 * Returns: Relative path name attached to output file name.
 *
 * Purpose: The namedfile uses the -O command line argument to take a data
 *          directory and puts it together with its default file name to
 *          come up with the file name needed for output.
 *
 * Called by: do_final_breakdown() in mod_tcplib.c
 *            do_tcplib_final_converse() in mod_tcplib.c
 *            tcplib_do_telnet_duration() in mod_tcplib.c
 *            tcplib_do_telnet_interarrival() in mod_tcplib.c
 *            tcplib_do_telnet_pktsize() in mod_tcplib.c
 *            tcplib_do_ftp_itemsize() in mod_tcplib.c
 *            tcplib_do_ftp_control_size() in mod_tcplib.c
 *            tcplib_do_smtp() in mod_tcplib.c
 *            tcplib_do_nntp_itemsize() in mod_tcplib.c
 *            tcplib_do_http_itemsize() in mod_tcplib.c
 * 
 * ***************************************************************************/
char * namedfile(
    char * real)  /* Default file name for the output file */
{
    static char buffer[256];    /* Buffer to store the full file name */

    sprintf(buffer, "%s%s", output_dir, real);

    return buffer;
}




/* **************************************************************************
 * 
 * Function Name: do_final_breakdown
 * 
 * Returns: Nothing
 *
 * Purpose: To generate the final breakdown file.  More specifically, to
 *          generate the one line in the breakdown file associated with
 *          the input file that is currently being traced.
 *
 * Called by: tcplib_done()    in mod_tcplib.c
 *            tcplib_newfile() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
static void do_final_breakdown(
    char* filename       /* The name of the current trace data file */
    )
{
    int i;            /* Looping variable */
    FILE* fil;        /* File descriptor for the traffic breakdown file */
    long file_pos;    /* Offset within the traffic breakdown file */
    int a2b_len;      /* What kind of port is A's port? */
    int b2a_len;      /* What kind of port is B's port? */
    tcp_pair *ptp;    /* A pointer to a conversation struct */

    /* This is the header for the traffic breakdown file.  It follows the
     * basic format of the original TCPLib breakdown file, but has been
     * modified to accomodate the additions that were made to TCPLib */
    char *header = "stub\tsmtp\tnntp\ttelnet\tftp\thttp\tphone\tconv\n";

    if(!(fil = fopen(namedfile(TCPLIB_BREAKDOWN_FILE), "a"))) {
	perror("Opening Breakdown File");
	exit(1);
    }

    fseek(fil, 0, SEEK_END);
    file_pos = ftell(fil);

    /* Basically, we're checking to see if this file has already been
     * used.  We have the capability to both start a new set of data
     * based on a trace file, or we have the ability to incorporate one
     * trace file's data into the data from another trace.  This would
     * have the effect of creating a hybrid traffic pattern, that matches
     * neither of the sources, but shares characteristics of both. */
    if(file_pos < strlen(header)) {
	fprintf(fil, "%s", header);
    }

    /* We only do this next part if we actually have a file name.  In
     * earlier revisions, sending a NULL filename signified the end of
     * all trace files.  At this point, a NULL file name has no useful
     * purpose, so we ignore it completely. */
    if(filename) {

	/* The breakdown file line associated with each trace file is
	 * prefaced with the trace file's name.  This was part of the
	 * original TCPLib format. */
	fprintf(fil, "%s", filename);

	/* Here, we're both setting up the tpclib_breakdown_totals, and
	 * also removing the breakdown totals from the previous file
	 */
    	for(i = 0; i < NUM_APPS; i++)
	    tcplib_breakdown_total[i] = 0;

	/* Scan through the entire set of conversations, and pull out
	 * the number of conversations for each traffic type */
	for(i = 0; i < num_tcp_pairs; i++) {
	    ptp = ttp[i];

	    if((a2b_len = breakdown_type(ptp->addr_pair.a_port)) != -1)
		tcplib_breakdown_total[a2b_len]++;
	    
	    if((b2a_len = breakdown_type(ptp->addr_pair.b_port)) != -1)
		tcplib_breakdown_total[b2a_len]++;
	}

	/* Print out the ratio of conversations of each traffic type
	 * to total number of converstaions observed in the trace file
	 */
	for(i = 0; i < NUM_APPS; i++) {
	    fprintf(fil, "\t%.4f", ((float)tcplib_breakdown_total[i])/num_tcp_pairs);
	}

	/* Place holders for phone and converstation intervals.  The phone
	 * type was never fully developed in the original TCPLib implementation.
	 * At the current time, we don't consider phone type conversations.
	 * The placeholder for conversation intervals allows us to use TCPLib's
	 * existing setup for aquiring statistics.  Without a placeholder in
	 * the breakdown file, TCPLib won't recognize this particular item, and
	 * in the generation of statistically equivalent traffic patterns, the
	 * interval between converstaions is of utmost importance, especially
	 * as far as the scalability of traffic is concerned. */
	fprintf(fil, "\t%.4f\t%.4f\n", (float)0, (float)0);

    }

    fclose(fil);
    fclose(hist_file);
}









/* **************************************************************************
 * 
 * Function Name: breakdown_type
 * 
 * Returns: The generic type of connection associated with "port"
 *
 * Purpose: To convert the port given to the function to the appropriate
 *          TCPLib type port.  As we come across other ports that have the
 *          same basic characteristics as TCPLib type, we can just add
 *          them here.
 *
 * Called by: tcplib_read()        in mod_tcplib.c
 *            do_final_breakdown() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
static int breakdown_type(
    int port)   /* What real port to examine */
{
    /* This was added in order to handle generating statistics from traffic
     * that was created by the traffic generator.  Since the traffic from the
     * the traffic generator is usually sent to non-standard ports, we need
     * be able to pick out that traffic for analysis.  This is where the
     * ipport_offset comes in.  We know what the offset is, so we just 
     * subtract it.  Big Bubba, No Trubba. */
    port -= ipport_offset;

    switch(port) {
      case IPPORT_LOGIN:
      case IPPORT_KLOGIN:
      case IPPORT_OLDLOGIN:
      case IPPORT_FLN_SPX:
      case IPPORT_UUCP_LOGIN:
      case IPPORT_KLOGIN2:
      case IPPORT_NLOGIN:
      case IPPORT_TELNET:
	return TCPLIBPORT_TELNET;
	break;

      case IPPORT_FTP_CONTROL:
/*      case IPPORT_FTP_DATA: */
/* We take out FTP data port because the control connections will be the 
 * deciding factors for the FTP connections */
	return TCPLIBPORT_FTP;
	break;

      case IPPORT_SMTP:
	return TCPLIBPORT_SMTP;
	break;

      case IPPORT_NNTP:
	return TCPLIBPORT_NNTP;
	break;

      case IPPORT_HTTP:
	return TCPLIBPORT_HTTP;
	break;
    
      default:
	return TCPLIBPORT_NONE;
    }

    return TCPLIBPORT_NONE;
}

/* End Breakdown Stuff */







/* Begin Next Conversation Stuff */

/* **************************************************************************
 * 
 * Function Name: do_tcplib_next_converse
 * 
 * Returns: Nothing
 *
 * Purpose: This function takes a new conversation and deals with the time
 *          between successive conversations.  If an entry in the breakdown
 *          table already exists with that particular time, then the counter
 *          is simply incremented.  If not, then a new table is made with a
 *          space for the new table item.  We're using arrays, but a change
 *          might be made to use a linked list before too long.
 *
 * Called by: tcplib_newconn() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
static void do_tcplib_next_converse(
    tcp_pair *ptp)    /* This conversation */
{
    int i;       /* Looping variable */
    int	j;       /* Looping variable */
    int time;    /* Time difference between the first packet in this
		  * conversation and the first packet in the previous
		  * conversation.  Basically, this is the time between
		  * new conversations. */
    struct tcplib_next_converse *new_breakdown;

    /* The time 0.0 is what we'll get if this is the first conversation 
     * we've seen in this data file. */
    if(   (last_converse.tv_sec == 0) 
       && (last_converse.tv_usec == 0)) {

	/* All we do is store the time for this conversation as the
	 * baseline and go on.  There's really no data here. */
	last_converse.tv_sec = ptp->first_time.tv_sec;
	last_converse.tv_usec = ptp->first_time.tv_usec;
	return;
    }

    /* We want the time difference in milliseconds.  Perhaps this will
     * get changed to microseconds. */
    time = (ptp->first_time.tv_sec - last_converse.tv_sec)*1000 +
	   (ptp->first_time.tv_usec - last_converse.tv_usec)/1000;

    /* We're going to try and update the table of conversation intervals.
     * If there's an entry in the table/list for this exact time, we'll
     * use it.  Otherwise, we'll have to create another entry for it.
     */
    for(i = 0; i < size_next_converse_breakdown; i++) {

	/* If this value of time is present, we're all set. */
	if(next_converse_breakdown[i].time == time) {
	    next_converse_breakdown[i].count++;
	    last_converse.tv_sec = ptp->first_time.tv_sec;
	    last_converse.tv_usec = ptp->first_time.tv_usec;
	    
	    return;
	} else if(next_converse_breakdown[i].time > time)

	    /* If it's not present, it gets uglier */
	    break;
    }

    /* This section could probably use being changed to linked list.  
     * The nice thing about the arrays is that they're quickly accessable,
     * but they use a hell of a lot of memory, especially since the array
     * is going to be fairly sparse. */

    /* Increasing the size of the breakdown table */
    size_next_converse_breakdown++;

    /* Create a new array */
    new_breakdown = (struct tcplib_next_converse *)malloc(sizeof(struct tcplib_next_converse)
							  * size_next_converse_breakdown);

    /* Copying the array over */
    for(j = 0; j < i; j++) {
	new_breakdown[j].time = next_converse_breakdown[j].time;
	new_breakdown[j].count = next_converse_breakdown[j].count;
    }

    /* Adding the new breakdown item */
    new_breakdown[i].time = time;
    new_breakdown[i].count = 1;

    /* Continuing to copy the array over */
    for(j = (i+1); j < size_next_converse_breakdown; j++){
	new_breakdown[j].time = next_converse_breakdown[j-1].time;
	new_breakdown[j].count = next_converse_breakdown[j-1].count;
    }

    /* Reassigning the pointers */
    free(next_converse_breakdown);

    next_converse_breakdown = new_breakdown;

    /* Updating the last conversation timer */
    last_converse.tv_sec = ptp->first_time.tv_sec;
    last_converse.tv_usec = ptp->first_time.tv_usec;

    return;
}

/* End of the breakdown section */









/* **************************************************************************
 * 
 * Function Name: file_extract
 * 
 * Returns: Pointer to an array of data extracted from file.
 *
 * Purpose: This is a fairly generic function which will be used by all of
 *          the data collecting functions to aquire previous data points
 *          from data files before merging the data from the current trace
 *          file into the statistics already accumulated.
 *
 * Called by: do_tcplib_final_converse() in mod_tcplib.c
 *            tcplib_do_telnet_duration() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
static struct tcplib_next_converse * file_extract(
    FILE* fil,    /* File we're extracting information from */
    int *lines,   /* Number of lines in the file */
    int *count)   /* Running sum of total # of points in the file */
{
    char buffer[256];       /* Character buffer used to extract data from
			     * the input file. */
    int filelines = 0;      /* Number of lines in the file */
    struct tcplib_next_converse *old_stuff; 
                            /* Data extracted from the file */
    float temp1, temp2;     /* Temporaries used to read data from the file */
    int local_count = 0;    /* Keeps track of total items read */
    int i, j;               /* Looping variables */

    /* Make sure we're starting at the beginning */
    fseek(fil, 0, SEEK_SET);

    /* Counting number of lines */
    while(fgets(buffer, 255, fil))
	filelines++;

    /* The first line is worthless, so don't count it. */
    filelines--;
    fseek(fil, 0, SEEK_SET);

    /* Get the first line out of the way */
    fgets(buffer, 255, fil);

    /* Set up an array to handle the data in the file */
    old_stuff = (struct tcplib_next_converse *)malloc(sizeof(struct tcplib_next_converse) 
						      * filelines);

    /* Yanking the data from the file */
    for(i = 0; i < filelines-1; i++) {
	fscanf(fil, "%f\t%f\t%d\t%d\n",
	       &temp1, &temp2,
	       &j, &(old_stuff[i].count));

	old_stuff[i].time = (int)temp1;

	/* Incrementing the count */
	local_count += old_stuff[i].count;
    }

    /* Update the information to be passed back to the calling function */
    *lines = filelines;
    *count = local_count;

    return old_stuff;
}









/* **************************************************************************
 * 
 * Function Name: do_tcplib_final_converse
 * 
 * Returns: Nothing
 *
 * Purpose: To generate a new line in the breakdown file which shows the
 *          conversation percentages viewed in the file that is currently
 *          open, but has just been ended.
 *
 * Called by: tcplib_done() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
static void do_tcplib_final_converse()
{
    int i;                  /* Looping Variable */
    FILE* fil;              /* The Breakdown file stream */
    int count = 0;          /* Total number of items */
    int curr_count = 0;     /* Number of items with this conversation interval */
    FILE* old;              /* The previous breakdown file.  Basically, we read
			     * in the old file, extract its data, and patch in
			     * the new data. */
    int filelines = 0;      /* How many lines (entries) are in the file */
    struct tcplib_next_converse *old_stuff = NULL;
                            /* Structure to hold the data from the old conversation
			     * breakdown file. */
    int j;                  /* Looping Variable */
    int temp;               /* The time of this conversation interval */
    int thisone;            /* The number of instances with this conversation
			     * interval.  Used for printing out only */

    /* First section is checking for a previous version of the breakdown file.
     * If one exists, we need to open it up, and pull all the data out of
     * it, so we can patch our data into what's already present. */
    if((old = fopen(namedfile(TCPLIB_NEXT_CONVERSE_FILE), "r"))) {

	old_stuff = file_extract(old, &filelines, &count);

	fclose(old);
    }

    /* Adding the number of entries was have from this run to the
     * total count we've got from the file. */
    for(i = 0; i < size_next_converse_breakdown; i++) {
	count += next_converse_breakdown[i].count;
    }

    if(!(fil = fopen(namedfile(TCPLIB_NEXT_CONVERSE_FILE), "w"))) {
	perror("Error opening TCPLib Conversation Interarrival file");
	exit(1);
    }

    /* File header */
    fprintf(fil, "Conversation Interval Time (ms)\t%% Interarrivals\tRunning Sum\tCounts\n");
    
    i = 0;
    curr_count = 0;

    /* Setting up the conditions for the next loop */
    if(old_stuff)
	j = 0;
    else
	j = EMPTY;


    /* Basically what happens here is that we want to spit out the data
     * that we've collected back into the file.  Basically, we're merging
     * the data.  So, we start at the conversation time being at basically
     * 0, and run up from there.  If both tables have an entry for a time, X,
     * we add up the counts for that time, and print the merged data for
     * that time.  If only one has an entry, then we print only its data.
     * It just looks complicated. */
    while((i != EMPTY) || (j != EMPTY)) {

	if(   (i != EMPTY)
	   && (   (j == EMPTY) 
	       || (next_converse_breakdown[i].time < old_stuff[j].time))) {
	    curr_count += next_converse_breakdown[i].count;
	    temp = next_converse_breakdown[i].time;
	    thisone = next_converse_breakdown[i].count;
	    i++;
	} else if(   (j != EMPTY)
		  && (   (i == EMPTY) 
		      || (next_converse_breakdown[i].time > old_stuff[j].time))) {
	    curr_count += old_stuff[j].count;
	    temp = old_stuff[j].time;
	    thisone = old_stuff[j].count;
	    j++;
	} else {
	    curr_count += next_converse_breakdown[i].count;
	    curr_count += old_stuff[j].count;
	    temp = next_converse_breakdown[i].time;
	    thisone = next_converse_breakdown[i].count + old_stuff[j].count;
	    j++;
	    i++;
	}
   
	/* We've run out of items in this set, so mark it as empty so
	 * we don't bother checking anymore */
	if(i >= size_next_converse_breakdown)
	    i = EMPTY;

	/* We've run out of items in this set, so mark it as empty so
	 * we don't bother checking anymore */
	if(j >= filelines)
	    j = EMPTY;

	/* Print out this line. */
	fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		(float)(temp),
		(((float)curr_count)/count),
		curr_count,
		thisone);
	
    }

    /* We're done, so close the file */
    fclose(fil);

    /* Let's go ahead and free up the data */
    if(old_stuff) {
	free(old_stuff);
	old_stuff = NULL;
    }

    return;
}

/* End Next Conversation Stuff */










/* Begin Telnet stuff */

/* **************************************************************************
 * 
 * Function Name: is_telnet_port
 * 
 * Returns: TRUE/FALSE whether a given port is a telnet/login type port.
 *
 * Purpose: To accept a port number and determine whenter or not the port
 *          would exhibit the characteristics of a telnet/login port.
 *
 * Called by: tcplib_read()                in mod_tcplib.c
 *            tcplib_do_telnet_duration()  in mod_tcplib.c
 *            tcplib_add_telnet_interval() in mod_tcplib.c
 * 
 * ***************************************************************************/
int is_telnet_port(
    int port)       /* The port we're looking at */
{
    /* Handle the offsets associated with packet traces generated by
     * trafgen. */
    port -= ipport_offset;

    switch(port) {
      case IPPORT_LOGIN:
      case IPPORT_KLOGIN:
      case IPPORT_OLDLOGIN:
      case IPPORT_FLN_SPX:
      case IPPORT_UUCP_LOGIN:
      case IPPORT_KLOGIN2:
      case IPPORT_NLOGIN:
      case IPPORT_TELNET:
	return TRUE;
	break;

      default:
	return FALSE;
    }
}









/* **************************************************************************
 * 
 * Function Name: tcplib_do_telnet_duration
 * 
 * Returns: Nothing
 *
 * Purpose: To collect information about the duration of a telnet
 *          conversation, and merge this information with data from
 *          previous runs of this module, if such data exists.
 *
 * Called by: tcplib_do_telnet() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
void tcplib_do_telnet_duration()
{
    int i;                   /* Looping variable */
    tcp_pair *pair;          /* Host pair */
    int max_size = 0;        /* duration of the longest telnet connection */
    int temp;                /* Used to store durations of conversations */
    int count = 0;           /* Number of connections */
    int curr_count = 0;      /* Total number of connections */
    int *count_list = NULL;  /* The array of merged data points */
    FILE* fil;               /* output file descriptor */
    FILE* old;               /* input file descriptor */
    int filelines = 0;       /* Number of lines in the input file */
    struct tcplib_next_converse *old_stuff = NULL;
                             /* Array containing the data from the input file */

    /* This section reads in the data from the existing telnet duration
     * file in preparation for merging with the current data. */
    if((old = fopen(namedfile(TCPLIB_TELNET_DURATION_FILE), "r"))) {

	old_stuff = file_extract(old, &filelines, &count);

	/* What is this 100 for?  I forget */
	for(i = 0; i < filelines; i++) {

	    /* So we're subtracting 100ms from everything, but why? */
	    old_stuff[i].time -= 100;
/*	    count -= 100;*/
	}

	/* Keeping track of the maximum duration */
	max_size = old_stuff[(filelines-1)].time;

	fclose(old);
    }   

    /* First job, find the stream with the longest duration */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need these stats if it's telnet */
	if(   is_telnet_port(pair->addr_pair.a_port)
	   || is_telnet_port(pair->addr_pair.b_port)) {

	    /* Find the conversation with the longest duration.
	     * This will determine the length of the array we'll need
	     * to store our counts
	     */
	    temp = ((pair->last_time.tv_sec - pair->first_time.tv_sec)*1000) +
		   ((pair->last_time.tv_usec - pair->first_time.tv_usec)/1000);

	    /* Update the maximum duration */
	    if(temp > max_size)
		max_size = temp;

	    count++;

	}
    }

    /* Allocate the array */
    count_list = (int *)malloc(sizeof(int) * ((max_size/100)+1));

    /* Reset the array */
    for(i = 0; i < ((max_size/100)+1); i++)
	count_list[i] = 0;

    /* Fill the array */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* Only work this for telnet connections */
	if(   is_telnet_port(pair->addr_pair.a_port)
	   || is_telnet_port(pair->addr_pair.b_port)) {

	    /* convert the time difference to ms */
	    temp = ((pair->last_time.tv_sec - pair->first_time.tv_sec)*1000) +
		   ((pair->last_time.tv_usec - pair->first_time.tv_usec)/1000);

	    /* So temp is per 100ms */
	    temp /= 100;

	    /* increment the number of instances at this time. */
	    count_list[temp]++;
	}
    }

    /* Integrate the old data */
    if(old_stuff)
	for(i = 0; i < filelines; i++)
	    count_list[(old_stuff[i].time/100)] += old_stuff[i].count;

    /* Open the file */
    if(!(fil = fopen(namedfile(TCPLIB_TELNET_DURATION_FILE), "w"))) {
	perror("Unable to open Telnet Duration Data file for TCPLib");
	exit(1);
    }

    fprintf(fil, "Duration (ms)\t%% Conversations\tRunning Sum\tCounts\n");

    /* Output data to the file */
    for(i = 0; i < ((max_size/100)+1); i++) {
	curr_count += count_list[i];

	if(count_list[i]) {
	    fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		    (float)((i+1)*100),           /* Here is where we add that 100ms */
		    (((float)curr_count)/count),
		    curr_count,
		    count_list[i]);
	}
    }

    fclose(fil);

    /* freeing up the temporary things */
    free(count_list);

    if(old_stuff)
	free(old_stuff);
}









/* **************************************************************************
 * 
 * Function Name: tcplib_add_telnet_interarrival
 * 
 * Returns: Nothing
 *
 * Purpose: This function takes the current packet and computes the time
 *          between the current packet and the previous packet.  This value
 *          is then added to the list of telnet interarrivals.  These values
 *          will be used at a later time.
 *
 * Called by: tcplib_read() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
void tcplib_add_telnet_interarrival(
    tcp_pair *ptp,              /* This conversation */
    struct timeval* ptp_saved)  /* The time of the last packet in the conversation */
{
    int temp = 0;    /* time differential between packets */

    /* Basically, I need the current time AND the time of the previous packet
     * BOTH right now.  As far as I can see, this function won't get called
     * until the previous packet time has already been overwritten by the
     * current time.  This makes obtaining interarrival times more difficult.
     */

    /* Answer - changed the original program.  We added the pmstruct thing
     * to the original TCPTrace which allows a module to store information
     * about a connection.  Quite handy.  Thanks, Dr. Ostermann */

    /* We only need to do this stuff if this connection is a telnet connection */
    if(   is_telnet_port(ptp->addr_pair.a_port)
       || is_telnet_port(ptp->addr_pair.b_port)){

	/* First packet has no interarrival time */
	if(   (ptp->last_time.tv_sec == ptp->first_time.tv_sec)
	   && (ptp->last_time.tv_usec == ptp->first_time.tv_usec)) {

	    /* If this is the first packet we've seen, then all we need
	     * to do is store this tiem in the ptp_saved structure and
	     * throw it back.  We'll be able to get some data the next
	     * time. */
	    ptp_saved->tv_sec = ptp->last_time.tv_sec;
	    ptp_saved->tv_usec = ptp->last_time.tv_usec;
	    return;
	}
	
	/* Determining the time difference in ms */
	temp = (ptp->last_time.tv_sec - ptp_saved->tv_sec)*1000;
	temp += (ptp->last_time.tv_usec - ptp_saved->tv_usec)/1000;

	/* We're going to set an artificial maximum for telnet interarrivals
	 * for the case when someone (like me) would open a telnet session
	 * and just leave it open and not do anything on it for minutes or
	 * hours, or in some cases days.  Keeping track of the exact time
	 * for a connection like that is not worth the effort, so we just
	 * set a ceiling and if it's over the ceiling, we make it the
	 * ceiling. */
	if(temp > MAX_TEL_INTER_COUNT - 1)
	    temp = MAX_TEL_INTER_COUNT - 1;

	/* In this case, we know for a fact that we don't have a value of
	 * temp that larger than the array, so we just increment the count
	 */
	tcplib_telnet_interarrival_count[temp]++;

	/* now we just want to record this time and store it with TCPTrace
	 * until we need it - which will be the next time that this 
	 * conversation receives a packet. */
	ptp_saved->tv_sec = ptp->last_time.tv_sec;
	ptp_saved->tv_usec = ptp->last_time.tv_usec;
    }

    return;
}









    
/* **************************************************************************
 * 
 * Function Name: tcplib_do_telnet_interarrival
 * 
 * Returns: Nothing
 *
 * Purpose: To model integrate the old data for telnet interarrival times
 *          with the data gathered during this execution of the program.
 *
 * Called by: tcplib_do_telnet() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
void tcplib_do_telnet_interarrival()
{
    int i;                 /* Looping variable */
    FILE* fil;             /* Output file descriptor */
    int count = 0;         /* Number of connections */
    int curr_count = 0;    /* Total number of connections */
    FILE* old;             /* Input file descriptor */
    struct tcplib_next_converse *old_stuff;
                           /* Array containing data from the input file */
    int j;                 /* Looping variable */
    int filelines = 0;     /* Number of lines in the input file */

    /* Reads in the existing data from the telnet inter-arrival file
     * in preparation for merging with the data from this run */
    if((old = fopen(namedfile(TCPLIB_TELNET_INTERARRIVAL_FILE), "r"))) {

	old_stuff = file_extract(old, &filelines, &count);

	for(i = 0; i < filelines; i++)
	    old_stuff[i].time -= 1;

	j = 0;

	/* In this one, we keep only a limited number of data points.
	 * What we've got is a statically defined array which will not
	 * grow.  So we just read in the counts from the file, and apply
	 * them to the array we've kept */
	for(i = 0; i < MAX_TEL_INTER_COUNT; i++) {
	    while(old_stuff[j].time < i) {
		if(++j >= filelines)
		    break;
		    
		if((j < filelines) && (old_stuff[j].time == i))
		    tcplib_telnet_interarrival_count[i] += old_stuff[j].count;
	    }
	}

	fclose(old);
    }   

    /* Just figuring out how many total entries we have */
    count = 0;
    for(i = 0; i < MAX_TEL_INTER_COUNT; i++) {
	count += tcplib_telnet_interarrival_count[i];
    }

    /* Dumping the data out to the data file */
    if(!(fil = fopen(namedfile(TCPLIB_TELNET_INTERARRIVAL_FILE), "w"))) {
	perror("Error opening Telnet Interarrival file");
	exit(1);
    }

    fprintf(fil, "Interarrival Time (ms)\t%% Interarrivals\tRunning Sum\tCounts\n");
    
    for(i = 0; i < MAX_TEL_INTER_COUNT; i++) {
	curr_count += tcplib_telnet_interarrival_count[i];

	if(tcplib_telnet_interarrival_count[i]) {
	    fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		    (float)(i + 1),
		    (((float)curr_count)/count),
		    curr_count,
		    tcplib_telnet_interarrival_count[i]);
	}
    }

    fclose(fil);
}










/* **************************************************************************
 * 
 * Function Name: tcplib_do_telnet_packetsize
 * 
 * Returns: Nothing
 *
 * Purpose: To take the data on telnet packet sizes measured during this
 *          run of the program, merge them with any existing data, and 
 *          drop a data file.
 *
 * Called by: tcplib_do_telnet() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
void tcplib_do_telnet_packetsize()
{
    int i;               /* Looping variable */
    FILE* fil;           /* Output file descriptor */
    int count = 0;       /* Number of entries in the table */
    int curr_count = 0;  /* Total number of table entries */
    FILE* old;           /* Input file descriptor */
    char buffer[256];    /* Temp buffer used to count input lines */
    struct tcplib_next_converse old_stuff;  /* Array of previous data points */
    float temp1, temp2;  /* Data as read from the previous data file */
    int j;               /* Temporary variable - used to store count read from data file */

    /* In this section, we're readin in from the previous data file,
     * applying the data contained there to the data set that we've 
     * acquired during this run, and then dumping the merged data set
     * back out to the data file */
    if((old = fopen(namedfile(TCPLIB_TELNET_PACKETSIZE_FILE), "r"))) {

	/* Get the first line out of the way - first line is just text, no data */
	fgets(buffer, 255, old);

	/* Read the data one line at at time */
	while(!feof(old)) {
	    fscanf(old, "%f\t%f\t%d\t%d\n",
		   &temp1, &temp2,
		   &j, &(old_stuff.count));

	    old_stuff.time = ((int)temp1 - 1);

	    /* Making sure that the data we're reading is legal and that
	     * we don't overstep our array boundaries */
	    if(old_stuff.time >= MAX_TEL_PACK_SIZE_COUNT) {
		printf("Telnet packet payload too high - %d.  Truncating.\n", old_stuff.count);
		old_stuff.count = MAX_TEL_PACK_SIZE_COUNT - 1;
	    }

	    /* Applying the old data to our current data */
	    tcplib_telnet_packetsize_count[old_stuff.time] += old_stuff.count;
	}

	fclose(old);
    }   

    /* Figuring out how many data points we've got total */
    for(i = 0; i < MAX_TEL_PACK_SIZE_COUNT; i++) {
	count += tcplib_telnet_packetsize_count[i];
    }

    /* Opening the file, preparing it form rewriting */
    if(!(fil = fopen(namedfile(TCPLIB_TELNET_PACKETSIZE_FILE), "w"))) {
	perror("Error opening Telnet Packet Size file");
	exit(1);
    }

    /* Dropping the data back out to the file */
    fprintf(fil, "Packet Size (bytes)\t%% Packets\tRunning Sum\tCounts\n");
    
    for(i = 0; i < MAX_TEL_PACK_SIZE_COUNT; i++) {
	curr_count += tcplib_telnet_packetsize_count[i];

	if(tcplib_telnet_packetsize_count[i]) {
	    fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		    (float)(i + 1),
		    (((float)curr_count)/count),
		    curr_count,
		    tcplib_telnet_packetsize_count[i]);
	}
    }

    fclose(fil);
}








/* **************************************************************************
 * 
 * Function Name: tcplib_add_telnet_packetsize
 * 
 * Returns: Nothing
 *
 * Purpose: Takes a length as acquired from a telnet packet data size and
 *          increments the count of the telnet packet size table by one for
 *          entry which corresponds to that length.  If the packet size is
 *          larger than the allocated table allows, we truncate the packet
 *          size.
 *
 * Called by: tcplib_read() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
void tcplib_add_telnet_packetsize(
    int length)  /* The length of the packet to be added to the table */
{
    /* Checking to make sure we don't overrun our array bounds */
    if(length > MAX_TEL_PACK_SIZE_COUNT)
	length = MAX_TEL_PACK_SIZE_COUNT;

    /* Incrementing the table */
    tcplib_telnet_packetsize_count[length - 1]++;
}







/* **************************************************************************
 * 
 * Function Name: tcplib_do_telnet
 * 
 * Returns: Nothing
 *
 * Purpose: To invoke the functions needed to handle data acquisition for
 *          telnet.
 *
 * Called by: tcplib_done() in mod_tcplib.c
 * 
 * 
 * ***************************************************************************/
void tcplib_do_telnet()
{
    tcplib_do_telnet_duration();      /* Handles duration data */

    tcplib_do_telnet_interarrival();  /* Handles packet inter-arrival data */
    
    tcplib_do_telnet_packetsize();    /* Handles packet size data */
}

/* End Telnet Stuff */








/* Begin FTP Stuff */

/* **************************************************************************
 * 
 * Function Name: is_ftp_data_port
 * 
 * Returns: Boolean value.
 *
 * Purpose: To determine if the port number sent to the function corresponds
 *          to an FTP data port.
 *
 * Called by: tcplib_do_ftp_itemsize() in mod_tcplib.c
 * 
 * ***************************************************************************/
int is_ftp_data_port(
    int port)   /* Port number */
{
    /* Removing the port offset */
    port -= ipport_offset;

    if(port == IPPORT_FTP_DATA)
	return TRUE;

    return FALSE;
}






/* **************************************************************************
 * 
 * Function Name: is_ftp_control_port
 * 
 * Returns: Boolean value
 *
 * Purpose: To determine if the port number sent tot he function corresponds
 *          to an FTP control port.
 *
 * Called by: tcplib_do_ftp_control_size() in mod_tcplib.c
 * 
 * ***************************************************************************/
int is_ftp_control_port(
    int port)   /* Port number */
{
    /* Removing the port offset */
    port -= ipport_offset;

    if(port == IPPORT_FTP_CONTROL)
	return TRUE;

    return FALSE;
}



/* **************************************************************************
 * 
 * Function Name: tcplib_do_ftp_itemsize
 * 
 * Returns: Nothing
 *
 * Purpose: To generate the ftp.itemsize data file from the information
 *          collected on ftp transfer sizes.  This function also integrates
 *          new data with old data, if any old data exists.
 *
 * Called by: tcplib_do_ftp() in mod_tcplib.c
 * 
 * ***************************************************************************/
void tcplib_do_ftp_itemsize()
{
    int i;                    /* Looping variable */
    tcp_pair *pair;           /* The tcp pair associated with a particular packet */
    int max_size = 0;         /* The largest transfer size seen */
    int count = 0;            /* Looping variable */
    int curr_count = 0;       /* Looping variable */
    int *size_list = NULL;    /* Combined data sets */
    FILE* fil;                /* File pointer for updated data file */
    int temp = 0;             /* Temporary variable */
    FILE* old;                /* File pointer for old data file */
    char buffer[256];         /* Buffer to store a single line from the old data file */
    int filelines = 0;        /* Number of entries in the old data file */
    struct tcplib_next_converse *old_stuff = NULL; /* Table of old values */
    float temp1, temp2;       /* Temp variables to be read in from old data file */
    int j;                    /* Looping variable */

    /* If the an old data file exists, open it, read in its contents and store them
     * until they are integrated with the current data */
    if((old = fopen(namedfile(TCPLIB_FTP_ITEMSIZE_FILE), "r"))) {

	/* Counting number of lines */
	while(fgets(buffer, 255, old))
	    filelines++;

	filelines--;
	fseek(old, 0, SEEK_SET);

	/* Get the first line out of the way */
	fgets(buffer, 255, old);

	old_stuff = (struct tcplib_next_converse *)
	    malloc(sizeof(struct tcplib_next_converse) * filelines);

	/* Read in each line in the file and pick out the pieces of
	 * the file.  Store each important piece in old_stuff */
	for(i = 0; i < filelines; i++) {
	    fscanf(old, "%f\t%f\t%d\t%d\n",
		   &temp1, &temp2,
		   &j, &(old_stuff[i].count));

	    old_stuff[i].time = (int)temp1;
	    count += old_stuff[i].count;
	}

	/* The largest transfer item in the file will be found in its
	 * last entry.  So we just store this as the current max_size */
	max_size = old_stuff[(filelines-1)].time;

	fclose(old);
    }   


    /* First job, find the largest transfer size */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's FTP data */
	if(   is_ftp_data_port(pair->addr_pair.a_port)
	   || is_ftp_data_port(pair->addr_pair.b_port)){
	    
	    /* Now we know we're only dealing with FTP data... so
	     * we need to find the conversation with the largest
	     * size.
	     */
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    if(temp > max_size)
		max_size = temp;

	    count++;
	}
    }

    size_list = (int *)malloc(sizeof(int) * ((max_size)+1));

    for(i = 0; i < ((max_size/5)+1); i++) 
	size_list[i] = 0;

    /* fill out the array */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's FTP data */
	if(   is_ftp_data_port(pair->addr_pair.a_port)
	   || is_ftp_data_port(pair->addr_pair.b_port)){
	    
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    size_list[temp/5]++;
	}
    }

    /* Integrate the old data */
    if(old_stuff)
	for(i = 0; i < filelines; i++)
	    size_list[(old_stuff[i].time)] += old_stuff[i].count;

    if(!(fil = fopen(namedfile(TCPLIB_FTP_ITEMSIZE_FILE), "w"))) {
	perror("Unable to open FTP Itemsize Data file for TCPLib");
	exit(1);
    }

    fprintf(fil, "Article Size (bytes)\t%% Articles\tRunning Sum\tCounts\n");

    for(i = 0; i < ((max_size)+ 1); i++) {
	temp = i;

	curr_count += size_list[i];

	if(size_list[i]) {
	    fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		    (float)temp,
		    (((float)curr_count)/count),
		    curr_count,
		    size_list[i]);
	}
    }

    fclose(fil);

    free(size_list);

    if(old_stuff)
	free(old_stuff);

    return;
}


/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_ftp_num_items()
{
    /* No fucking clue ATM */

    /* Need to figure out how to know when the control connection has
     * spawned off new data connections.
     */
}

/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_ftp_control_size()
{
    int i;
    tcp_pair *pair;
    int max_size = 0;
    int count = 0;
    int curr_count = 0;
    int *size_list = NULL;
    FILE* fil;
    int temp = 0;
    FILE* old;
    char buffer[256];
    int filelines = 0;
    struct tcplib_next_converse *old_stuff = NULL;
    float temp1, temp2;
    int j;

    if((old = fopen(namedfile(TCPLIB_FTP_CTRLSIZE_FILE), "r"))) {

	/* Counting number of lines */
	while(fgets(buffer, 255, old))
	    filelines++;

	filelines--;
	fseek(old, 0, SEEK_SET);

	/* Get the first line out of the way */
	fgets(buffer, 255, old);

	old_stuff = (struct tcplib_next_converse *)malloc(sizeof(struct tcplib_next_converse) 
							  * filelines);

	for(i = 0; i < filelines; i++) {
	    fscanf(old, "%f\t%f\t%d\t%d\n",
		   &temp1, &temp2,
		   &j, &(old_stuff[i].count));

	    old_stuff[i].time = (int)temp1;
	    count += old_stuff[i].count;
	}

	max_size = old_stuff[(filelines-1)].time;

	fclose(old);
    }   


    /* First job, find the largest transfer size */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's FTP data */
	if(   is_ftp_control_port(pair->addr_pair.a_port)
	   || is_ftp_control_port(pair->addr_pair.b_port)){
	    
	    /* Now we know we're only dealing with FTP data... so
	     * we need to find the conversation with the largest
	     * size.
	     */
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    if(temp > max_size) {
		max_size = temp;
	    }

	    count++;
	}
    }

    size_list = (int *)malloc(sizeof(int) * (max_size+1));

    for(i = 0; i < (max_size+1); i++) 
	size_list[i] = 0;

    /* fill out the array */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's FTP data */
	if(   is_ftp_control_port(pair->addr_pair.a_port)
	   || is_ftp_control_port(pair->addr_pair.b_port)){
	    
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    size_list[temp]++;
	}
    }

    /* Integrate the old data */
    if(old_stuff)
	for(i = 0; i < filelines; i++)
	    size_list[(old_stuff[i].time)] += old_stuff[i].count;

    if(!(fil = fopen(namedfile(TCPLIB_FTP_CTRLSIZE_FILE), "w"))) {
	perror("Unable to open FTP Control size Data file for TCPLib");
	exit(1);
    }

    fprintf(fil, "Packet Size (bytes)\t%% Packets\tRunning Sum\tCounts\n");

    for(i = 0; i < (max_size+1); i++) {
	curr_count += size_list[i];

	if(size_list[i]) {
	    fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		    (float)i,
		    (((float)curr_count)/count),
		    curr_count,
		    size_list[i]);
	}
    }

    fclose(fil);

    free(size_list);

    if(old_stuff)
	free(old_stuff);

    return;
}

    

/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_ftp()
{
    tcplib_do_ftp_control_size();  /* Done */

    tcplib_do_ftp_num_items();     /* Not Done */

    tcplib_do_ftp_itemsize();      /* Done */
}

/* End of FTP Stuff */

/* Begin SMTP Stuff */

/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
int is_smtp_port(int port)
{
    port -= ipport_offset;

    if(port == IPPORT_SMTP)
	return TRUE;

    return FALSE;
}

/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_smtp()
{
    int i;
    tcp_pair *pair;
    int max_size = 0;
    int count = 0;
    int curr_count = 0;
    int *size_list = NULL;
    FILE* fil;
    int temp = 0;
    FILE* old;
    char buffer[256];
    int filelines = 0;
    struct tcplib_next_converse *old_stuff = NULL;
    float temp1, temp2;
    int j;

    if((old = fopen(namedfile(TCPLIB_SMTP_ITEMSIZE_FILE), "r"))) {

	/* Counting number of lines */
	while(fgets(buffer, 255, old))
	    filelines++;

	filelines--;
	fseek(old, 0, SEEK_SET);

	/* Get the first line out of the way */
	fgets(buffer, 255, old);

	old_stuff = (struct tcplib_next_converse *)malloc(sizeof(struct tcplib_next_converse) 
							  * filelines);

	for(i = 0; i < filelines; i++) {
	    fscanf(old, "%f\t%f\t%d\t%d\n",
		   &temp1, &temp2,
		   &j, &(old_stuff[i].count));

	    old_stuff[i].time = ((int)temp1 - 5);
	    count += old_stuff[i].count;
	}

	max_size = old_stuff[(filelines-1)].time;

	fclose(old);
    }   


    /* First job, find the largest mail size */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's FTP data */
	if(   is_smtp_port(pair->addr_pair.a_port)
	   || is_smtp_port(pair->addr_pair.b_port)){
	    
	    /* Now we know we're only dealing with SMTP data... so
	     * we need to find the conversation with the largest
	     * size.
	     */
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    if(temp > max_size)
		max_size = temp;

	    count++;
	}
    }

    size_list = (int *)malloc(sizeof(int) * ((max_size / 5)+1));

    for(i = 0; i < ((max_size/5)+1); i++) 
	size_list[i] = 0;

    /* fill out the array */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's SMTP data */
	if(   is_smtp_port(pair->addr_pair.a_port)
	   || is_smtp_port(pair->addr_pair.b_port)){
	    
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    size_list[(temp/5)]++;
	}
    }

    /* Integrate the old data */
    if(old_stuff)
	for(i = 0; i < filelines; i++)
	    size_list[(old_stuff[i].time/5)] += old_stuff[i].count;

    if(!(fil = fopen(namedfile(TCPLIB_SMTP_ITEMSIZE_FILE), "w"))) {
	perror("Unable to open SMTP Itemsize Data file for TCPLib");
	exit(1);
    }

    fprintf(fil, "Total Bytes\t%% Conversations\tRunning Sum\tCounts\n");

    for(i = 0; i < ((max_size / 5)+1); i++) {
	temp = (i+1) * 5;

	curr_count += size_list[i];

	if(size_list[i]) {
	    fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		    (float)temp,
		    (((float)curr_count)/count),
		    curr_count,
		    size_list[i]);
	}
    }

    fclose(fil);

    free(size_list);

    if(old_stuff)
	free(old_stuff);

    return;
}

/* Done SMTP Stuff */


/* Being NNTP Stuff */

/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
int is_nntp_port(int port)
{
    port -= ipport_offset;

    if(port == IPPORT_NNTP)
	return TRUE;

    return FALSE;
}


/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_nntp_itemsize()
{
    int i;
    tcp_pair *pair;
    int max_size = 0;
    int count = 0;
    int curr_count = 0;
    int *size_list = NULL;
    FILE* fil;
    int temp = 0;
    FILE* old;
    char buffer[256];
    int filelines = 0;
    struct tcplib_next_converse *old_stuff = NULL;
    float temp1, temp2;
    int j;

    if((old = fopen(namedfile(TCPLIB_NNTP_ITEMSIZE_FILE), "r")) != NULL) {

	/* Counting number of lines */
	while(fgets(buffer, 255, old))
	    filelines++;

	filelines--;
	fseek(old, 0, SEEK_SET);

	/* Get the first line out of the way */
	fgets(buffer, 255, old);

	old_stuff = (struct tcplib_next_converse *)malloc(sizeof(struct tcplib_next_converse) 
							  * filelines);

	for(i = 0; i < filelines; i++) {
	    fscanf(old, "%f\t%f\t%d\t%d\n",
		   &temp1, &temp2,
		   &j, &(old_stuff[i].count));

	    old_stuff[i].time = (int)temp1;
	    count += old_stuff[i].count;
	}

	max_size = old_stuff[(filelines-1)].time;

	fclose(old);
    }   


    /* First job, find the largest article size */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's NNTP data */
	if(   is_nntp_port(pair->addr_pair.a_port)
	   || is_nntp_port(pair->addr_pair.b_port)){
	    
	    /* Now we know we're only dealing with NNTP data... so
	     * we need to find the conversation with the largest
	     * size.
	     */
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    if(temp > max_size)
		max_size = temp;

	    count++;
	}
    }

    size_list = (int *)malloc(sizeof(int) * (max_size+1) / 1024);

    for(i = 0; i < (max_size+1); i++) 
	size_list[i/1024] = 0;

    /* fill out the array */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's NNTP data */
	if(   is_nntp_port(pair->addr_pair.a_port)
	   || is_nntp_port(pair->addr_pair.b_port)){
	    
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    size_list[temp/1024]++;
	}
    }

    /* Integrate the old data */
    if(old_stuff)
	for(i = 0; i < filelines; i++)
	    size_list[(old_stuff[i].time)/1024] += old_stuff[i].count;

    if(!(fil = fopen(namedfile(TCPLIB_NNTP_ITEMSIZE_FILE), "w"))) {
	perror("Unable to open NNTP Itemsize Data file for TCPLib");
	exit(1);
    }

    fprintf(fil, "Article Size (bytes)\t%% Articles\tRunning Sum\tCounts\n");

    for(i = 0; i < (max_size+1)/1024; i++) {
	curr_count += size_list[i];

	if(size_list[i]) {
	    fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		    (float)i,
		    (((float)curr_count)/count),
		    curr_count,
		    size_list[i]);
	}
    }

    fclose(fil);

    free(size_list);

    if(old_stuff)
	free(old_stuff);

    return;
}


/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_nntp_numitems()
{
    /* No fucking clue ATM */

    /* Basically we need to figure out how many different
     * articles are bundles up together?  I'm not quite sure
     * how the whole NNTP thing works anyways.
     */
}


/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_nntp()
{
    tcplib_do_nntp_itemsize();  /* Done */
    
    tcplib_do_nntp_numitems();  /* Not Done */
}

/* Done NNTP Stuff */

/* Being HTTP Stuff */

/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
int is_http_port(int port)
{
    port -= ipport_offset;

    if(port == IPPORT_HTTP)
	return TRUE;

    return FALSE;
}

/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_http_itemsize()
{
    int i;
    tcp_pair *pair;
    int max_size = 0;
    int count = 0;
    int curr_count = 0;
    int *size_list = NULL;
    FILE* fil;
    int temp = 0;
    FILE* old;
    char buffer[256];
    int filelines = 0;
    struct tcplib_next_converse *old_stuff = NULL;
    float temp1, temp2;
    int j;

    if((old = fopen(namedfile(TCPLIB_HTTP_ITEMSIZE_FILE), "r"))) {

	/* Counting number of lines */
	while(fgets(buffer, 255, old))
	    filelines++;

	filelines--;
	fseek(old, 0, SEEK_SET);

	/* Get the first line out of the way */
	fgets(buffer, 255, old);

	old_stuff = (struct tcplib_next_converse *)malloc(sizeof(struct tcplib_next_converse) 
							  * filelines);

	for(i = 0; i < filelines; i++) {
	    fscanf(old, "%f\t%f\t%d\t%d\n",
		   &temp1, &temp2,
		   &j, &(old_stuff[i].count));

	    old_stuff[i].time = ((int)temp1);
	    count += old_stuff[i].count;
	}

	max_size = old_stuff[(filelines-1)].time;

	fclose(old);
    }   


    /* First job, find the largest transfer size */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's HTTP data */
	if(   is_http_port(pair->addr_pair.a_port)
	   || is_http_port(pair->addr_pair.b_port)){
	    
	    /* Now we know we're only dealing with HTTP data... so
	     * we need to find the conversation with the largest
	     * size.
	     */
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    if(temp > max_size)
		max_size = temp;

	    count++;
	}
    }

    size_list = (int *)malloc(sizeof(int) * (max_size+1));

    for(i = 0; i < (max_size+1); i++) 
	size_list[i] = 0;

    /* fill out the array */
    for(i = 0; i < num_tcp_pairs; i++) {
	pair = ttp[i];

	/* We only need the stats if it's HTTP data */
	if(   is_http_port(pair->addr_pair.a_port)
	   || is_http_port(pair->addr_pair.b_port)){
	    
	    temp = (pair->a2b.data_bytes) + (pair->b2a.data_bytes);

	    size_list[temp]++;
	}
    }

    /* Integrate the old data */
    if(old_stuff)
	for(i = 0; i < filelines; i++)
	    size_list[(old_stuff[i].time)] += old_stuff[i].count;

    if(!(fil = fopen(namedfile(TCPLIB_HTTP_ITEMSIZE_FILE), "w"))) {
	perror("Unable to open HTTP Itemsize Data file for TCPLib");
	exit(1);
    }

    fprintf(fil, "Article Size (bytes)\t%% Articles\tRunning Sum\tCounts\n");

    for(i = 0; i < (max_size+1); i++) {
	temp = (i+1);

	curr_count += size_list[i];

	if(size_list[i]) {
	    fprintf(fil, "%.3f\t%.4f\t%d\t%d\n",
		    (float)temp,
		    (((float)curr_count)/count),
		    curr_count,
		    size_list[i]);
	}
    }

    fclose(fil);

    free(size_list);

    if(old_stuff)
	free(old_stuff);
}

    

/* **************************************************************************
 * 
 * Function Name: 
 * 
 * Returns: 
 *
 * Purpose: 
 *
 * Called by: 
 * 
 * 
 * ***************************************************************************/
void tcplib_do_http()
{
    tcplib_do_http_itemsize();
}

#endif /* LOAD_MODULE_TCPLIB */
