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

#include "tcptrace.h"


/* info that I keep about each plotter */
struct plotter_info {
    MFILE *fplot;		/* the file that hold the plot */
    tcb *p2plast;		/* the TCB that this goes with (if any) */
    timeval zerotime;		/* first time stamp in this plot (see -z) */
    char *filename;		/* redundant copy of name for debugging */
};



/* locally global parameters */
static int max_plotters;
static PLOTTER plotter_ix = NO_PLOTTER;
static char *temp_color = NULL;
static struct plotter_info *pplotters;


/* local routine declarations */
static char *xp_timestamp(PLOTTER pl, struct timeval time);
static char *TSGPlotName(tcb *plast, PLOTTER, char *suffix);
static void DoPlot(PLOTTER pl, char *fmt, ...);






/*
 * Return a string suitable for use as a timestamp in the xplot output.
 * sdo fix: originally, we were just plotting to the accuracy of 1/10 ms
 *   this was mostly to help keep the .xpl files from being too large.  However,
 *   on faster networks this just isn't enough, so we'll now use all 6 digits
 *   of the microsecond counter.  Note that there's no guarantee that the
 *   timestamps are really all that accurate!
 */
static char *
xp_timestamp(
    PLOTTER pl,
    struct timeval time)
{
    static char bufs[4][20];	/* several of them for multiple calls in one printf */
    static int bufix = 0;
    unsigned secs;
    unsigned usecs;
    unsigned decimal;
    char *pbuf;

    /* see if we're graphing from "0" */
    if (graph_time_zero) {
	struct plotter_info *ppi = &pplotters[pl];

	if (ZERO_TIME(&ppi->zerotime)) {
	    /* set "zero point" */
	    ppi->zerotime = time;
	}

	/* (in)sanity check */
	if (tv_lt(time,ppi->zerotime)) {
	    fprintf(stderr,"Internal error in plotting (plot file '%s')...\n\
ZERO-based X-axis plotting requested and elements are not plotted in\n\
increasing time order.  Try without the '-z' flag\n",
		    ppi->filename);
/* 	    exit(-5); */
	    time.tv_sec = time.tv_usec = 0;
	} else {
	    /* computer offset from first plotter point */
	    tv_sub(&time, ppi->zerotime);
	}
    }

    /* calculate time components */
    secs = time.tv_sec;
    usecs = time.tv_usec;
    decimal = usecs;

    /* use one of 4 rotating static buffers (for multiple calls per printf) */
    bufix = (bufix+1)%4;
    pbuf = bufs[bufix];

    sprintf(pbuf,"%u.%06u",secs,decimal);

    return(pbuf);
}



void
plot_init(void)
{
    max_plotters = 256;  /* just a default, make more on the fly */

    pplotters = MallocZ(max_plotters * sizeof(struct plotter_info));
}


static void
plotter_makemore(void)
{
    int new_max_plotters = max_plotters * 4;

    if (debug)
	fprintf(stderr,"plotter: making more space for %d total plotters\n",
		new_max_plotters);

    /* reallocate the memory to make more space */
    pplotters = ReallocZ(pplotters,
			 max_plotters * sizeof(struct plotter_info),
			 new_max_plotters * sizeof(struct plotter_info));

    max_plotters = new_max_plotters;
}




/* max number of letters in endpoint name */
/* (8 allows 26**8 different endpoints (209,000,000,000)
    probably plenty for now!!!!!) */
#define MAX_HOSTLETTER_LEN 8
char *
HostLetter(
     unsigned ix)
{
    static char name[MAX_HOSTLETTER_LEN+1];
    static char *pname;

    /* basically, just convert to base 26 */
    pname = &name[sizeof(name)-1];
    *pname-- = '\00';
    while (pname >= name) {
	unsigned digit = ix % 26;
	*pname-- = 'a'+digit;
	ix = ix / 26;
	if (ix == 0)
	    return(pname+1);
    }

    fprintf(stderr,"Fatal, too many hosts to name (max length %d)\n",
	    MAX_HOSTLETTER_LEN);
    exit(-1);
    return(NULL);  /* NOTREACHED */
}


char *
NextHostLetter(void)
{
    static int count = 0;
    return(HostLetter(count++));
}



static char *
TSGPlotName(
    tcb *plast,
    PLOTTER pl,
    char *suffix)
{
    static char filename[25];

    sprintf(filename,"%s2%s%s",
	    plast->host_letter, plast->ptwin->host_letter, suffix);

    return(filename);
}



static void
DoPlot(
     PLOTTER	pl,
     char	*fmt,
     ...)
{
    va_list	ap;
    MFILE *f = NULL;
    struct plotter_info *ppi;

    va_start(ap,fmt);

/*     if (!graph_tsg) */
/* 	return; */

    if (pl == NO_PLOTTER) {
	va_end(ap);
	return;
    }

    if (pl > plotter_ix) {
	fprintf(stderr,"Illegal plotter: %d\n", pl);
	exit(-1);
    }

    ppi = &pplotters[pl];

    if ((f = ppi->fplot) == NULL) {
	va_end(ap);
	return;
    }

    Mvfprintf(f,fmt,ap);
    if (temp_color) {
	Mfprintf(f," %s",temp_color);
	temp_color = NULL;
    }
    Mfprintf (f,"\n");

    va_end(ap);

    return;
}


PLOTTER
new_plotter(
    tcb *plast,
    char *filename,	/* if NULL, use default name from plast */
    char *title,
    char *xlabel,
    char *ylabel,
    char *suffix)
{
    PLOTTER pl;
    MFILE *f;
    struct plotter_info *ppi;

    ++plotter_ix;
    if (plotter_ix >= max_plotters) {
	plotter_makemore();
    }

    pl = plotter_ix;
    ppi = &pplotters[pl];

    if (filename == NULL)
	filename = TSGPlotName(plast,pl,suffix);
    else if (suffix != NULL) {
	char buf[100];
	sprintf(buf,"%s%s", filename, suffix);
	filename = buf;
    }

    if (debug)
	fprintf(stderr,"Plotter %d file is '%s'\n", pl, filename);

    if ((f = Mfopen(filename,"w")) == NULL) {
	perror(filename);
	return(NO_PLOTTER);
    }

    /* graph coordinates... */
    /*  X coord is timeval unless graph_time_zero is true */
    /*  Y is signed except when it's a sequence number */
    /* ugly hack -- unsigned makes the graphs hard to work with and is
       only needed for the time sequence graphs */
    /* suggestion by Michele Clark at UNC - make them double instead */
    Mfprintf(f,"%s %s\n",
	     graph_time_zero?"dtime":"timeval",
	     ((strcmp(ylabel,"sequence number") == 0)&&(!graph_seq_zero))?
	     "double":"signed");

    if (show_title)
        Mfprintf(f,"title\n%s\n", title);
    Mfprintf(f,"xlabel\n%s\n", xlabel);
    Mfprintf(f,"ylabel\n%s\n", ylabel);

    ppi->fplot = f;
    ppi->p2plast = plast;
    ppi->filename = strdup(filename);

    return(pl);
}


void
plotter_done(void)
{
    PLOTTER pl;
    MFILE *f;
    char *fname;

    for (pl = 0; pl < plotter_ix; ++pl) {
	struct plotter_info *ppi = &pplotters[pl];
	
	if ((f = ppi->fplot) == NULL)
	    continue;
	
	if (!ignore_non_comp ||
	    ((ppi->p2plast != NULL) && (ConnComplete(ppi->p2plast->ptp)))) {
	    Mfprintf(f,"go\n");
	    Mfclose(f);
	} else {
	    fname = ppi->p2plast->tsg_plotfile;
	    if (debug)
		fprintf(stderr,"Removing incomplete plot file '%s'\n",
			fname);
	    Mfclose(f);
	    if (unlink(fname) != 0)
		perror(fname);
	}
    }
}



void
plotter_temp_color(
    PLOTTER pl,
    char *color)
{
    if (colorplot)
	temp_color = color;
}


void
plotter_perm_color(
    PLOTTER pl,
    char *color)
{
    if (colorplot)
	DoPlot(pl,"%s",color);
}


void
plotter_line(
    PLOTTER pl,
    struct timeval	t1,
    u_long		x1,
    struct timeval	t2,
    u_long		x2)
{
    DoPlot(pl,"line %s %u %s %u",
	   xp_timestamp(pl,t1), x1,
	   xp_timestamp(pl,t2), x2);
}


void
plotter_dline(
    PLOTTER pl,
    struct timeval	t1,
    u_long		x1,
    struct timeval	t2,
    u_long		x2)
{
    DoPlot(pl,"dline %s %u %s %u",
           xp_timestamp(pl,t1), x1,
           xp_timestamp(pl,t2), x2);
}


void
plotter_diamond(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"diamond %s %u", xp_timestamp(pl,t), x);
}


void
plotter_dot(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"dot %s %u", xp_timestamp(pl,t), x);
}


void
plotter_plus(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"plus %s %u", xp_timestamp(pl,t), x);
}


void
plotter_box(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"box %s %u", xp_timestamp(pl,t), x);
}



void
plotter_arrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x,
    char	dir)
{
    DoPlot(pl,"%carrow %s %u", dir, xp_timestamp(pl,t), x);
}


void
plotter_uarrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_arrow(pl,t,x,'u');
}


void
plotter_darrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_arrow(pl,t,x,'d');
}


void
plotter_rarrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_arrow(pl,t,x,'r');
}


void
plotter_larrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_arrow(pl,t,x,'l');
}


void
plotter_tick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x,
    char		dir)
{
    DoPlot(pl,"%ctick %s %u", dir, xp_timestamp(pl,t), x);
}


void
plotter_dtick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'d');
}


void
plotter_utick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'u');
}


void
plotter_ltick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'l');
}


void
plotter_rtick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'r');
}


void
plotter_htick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'h');
}


void
plotter_vtick(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    plotter_tick(pl,t,x,'v');
}



/* don't plot ANYTHING, just make sure ZERO point is set! */
void
plotter_nothing(
    PLOTTER pl,
    struct timeval	t)
{
    char *ret;
    ret = xp_timestamp(pl,t);
    if (debug > 10)
	printf("plotter_nothing(%s) gets '%s'\n", ts2ascii(&t), ret);
}



void
plotter_text(
    PLOTTER pl,
    struct timeval	t,
    u_long		x,
    char		*where,
    char		*str)
{
    DoPlot(pl,"%stext %s %u", where, xp_timestamp(pl,t), x);
    /* fix by Bill Fenner - Wed Feb  5, 1997, thanks */
    /* This is a little ugly.  Text commands take 2 lines. */
    /* A temporary color could have been */
    /* inserted after that line, but would NOT be inserted after */
    /* the next line, so we'll be OK.  I can't think of a better */
    /* way right now, and this works fine (famous last words) */
    DoPlot(pl,"%s", str);
}


/* high-level line-drawing package */
struct pl_line {
    char *color;
    char *label;
    int last_y;
    timeval last_time;
    PLOTTER plotter;
    Bool labelled;
};


PLINE
new_line(
    PLOTTER plotter,
    char *label,
    char *color)
{
    struct pl_line *pl;

    pl = MallocZ(sizeof(struct pl_line));
    pl->plotter = plotter;
    pl->label = label;
    pl->color = color;

    return(pl);
}


void
extend_line(
    PLINE pline,
    timeval xval,
    int yval)
{
    PLOTTER p;

    if (!pline)
	return;

    p = pline->plotter;

#ifdef OLD
    /* attach a label to the first non-zero point */
    if (!pline->labelled) {
	if (yval != 0) {
	    plotter_temp_color(p, pline->color);
	    plotter_text(p, xval, yval, "l", pline->label);
	    pline->labelled = 1;
	}
    }
#endif

    /* attach a label midway on the first line segment above 0 */
    /* for whom the second point is NOT 0 */
    if (!pline->labelled) {
	if ((yval != 0) && (!ZERO_TIME(&pline->last_time))) {
	    timeval tv_elapsed;
	    timeval tv_avg;
	    int avg_yval;

	    /* computer elapsed time for these 2 points */
	    tv_elapsed = xval;
	    tv_sub(&tv_elapsed,pline->last_time);

	    /* divide elapsed time by 2 */
	    tv_elapsed.tv_sec /= 2;
	    tv_elapsed.tv_usec /= 2;

	    /* add 1/2 of the elapsed time to the oldest point */
	    /* (giving us the average time) */
	    tv_avg = pline->last_time;
	    tv_add(&tv_avg, tv_elapsed);

	    /* average the Y values */
	    avg_yval = (1 + pline->last_y+yval)/2;
	    /* (rounding UP, please) */

	    /* draw the label */
	    plotter_temp_color(p, pline->color);
	    plotter_text(p, tv_avg, avg_yval, "l", pline->label);

	    /* remember that it's been done */
	    pline->labelled = 1;
	}
    }

    /* draw a dot at the current point */
    plotter_perm_color(p, pline->color);
    plotter_dot(p, xval, yval);

    /* if this isn't the FIRST point, connect with a line */
    if (!ZERO_TIME(&pline->last_time)) {
	plotter_line(p,
		     xval, yval,
		     pline->last_time, pline->last_y);
    }

    /* remember this point for the next line segment */
    pline->last_time = xval;
    pline->last_y = yval;
}
