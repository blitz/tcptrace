/* 
 * tcptrace.c - turn protocol monitor traces into xplot
 * 
 * Author:	Shawn Ostermann
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#include "tcptrace.h"
#include <stdarg.h>


/* locally global parameters */
static int max_plotters;
static FILE **fplot;
static tcb **p2plast;
static PLOTTER plotter_ix = NO_PLOTTER;
static char *temp_color = NULL;


/* local routine declarations */
static char *xp_timestamp(struct timeval time);
static char *TSGPlotName(tcb *plast, PLOTTER);
static void DoPlot(PLOTTER pl, char *fmt, ...);





/*
 * Return a string suitable for use as a timestamp in the xplot output.
 * (Currently rounds to the nearest 1/10 millisecond)
 */
static char *
xp_timestamp(
    struct timeval time)
{
    static char bufs[4][20];	/* several of them for multiple calls in one printf */
    static int bufix = 0;
    unsigned secs = time.tv_sec;
    unsigned usecs = time.tv_usec;
    unsigned decimal = (usecs + 50) / 100;
    char *pbuf;

    pbuf = bufs[(bufix++)%4];

    sprintf(pbuf,"%u.%04u",secs,decimal);
    return(pbuf);
}



void
plot_init()
{
    max_plotters = 2*max_tcp_pairs;

    fplot = (FILE **) malloc(max_plotters * sizeof(FILE *));
    if (!fplot) {
	perror("fplot malloc");
	exit(-1);
    }

    p2plast = (tcb **) malloc(max_plotters * sizeof(tcb *));
    if (!p2plast) {
	perror("p2plast malloc");
	exit(-1);
    }
    bzero(fplot,  max_plotters * sizeof(FILE *));
    bzero(p2plast,max_plotters * sizeof(tcb *));
}



char *
HostLetter(
     u_int ix)
{
    static char name[10];
    char ch1;
    char ch2;

    ch1 = ix / 26;
    ch2 = ix % 26;
	
    if (ix < 26) {
	sprintf(name,"%c",'a' + ch2);
    } else if (ix < (26*26)) {
	sprintf(name,"%c%c", 'a' + ch1 - 1, 'a' + ch2);
    } else {
	fprintf(stderr,"Fatal, too many hosts to name\n");
	exit(-1);
    }

    return(name);
}



static char *
TSGPlotName(
    tcb *plast,
    PLOTTER pl)
{
    static char filename[10];

    sprintf(filename,"%s2%s.xpl",
	    plast->host_letter, plast->ptwin->host_letter);

    return(filename);
}



static void
DoPlot(
     PLOTTER	pl,
     char	*fmt,
     ...)
{
    va_list	ap;
    FILE *f = NULL;

    va_start(ap,fmt);

    if (!plotem)
	return;

    if (pl == NO_PLOTTER)
	return;

    if (pl > plotter_ix) {
	fprintf(stderr,"Illegal plotter: %d\n", pl);
	exit(-1);
    }

    if ((f = fplot[pl]) == NULL)
	return;

    if (temp_color) {
	fprintf(f,"%s ",temp_color);
	temp_color = NULL;
    }

    vfprintf(f,fmt,ap);
    fprintf (f,"\n");

    va_end(ap);

    return;
}


PLOTTER
new_plotter(
     tcb *plast,
     char *title)
{
    PLOTTER pl;
    FILE *f;
    char *filename;

    ++plotter_ix;
    if (plotter_ix >= max_plotters) {
	fprintf(stderr,"No more plotters\n");
	return(NO_PLOTTER);
    }

    pl = plotter_ix;

    filename = TSGPlotName(plast,pl);

    if (debug)
	fprintf(stderr,"Plotter %d file is '%s'\n", pl, filename);

    if ((f = fopen(filename,"w")) == NULL) {
	perror(filename);
	return(NO_PLOTTER);
    }

    fprintf(f,"timeval unsigned\n");
    fprintf(f,"title\n%s\n", title);

    fplot[pl] = f;
    p2plast[pl] = plast;
    plast->tsg_plotfile = strdup(filename);
    return(pl);
}


void
plotter_done()
{
    PLOTTER pl;
    FILE *f;
    char *fname;

    for (pl = 0; pl < plotter_ix; ++pl) {
	if ((f = fplot[pl]) == NULL)
	    continue;
	if (!ignore_non_comp || ConnComplete(p2plast[pl]->ptp)) {
	    fprintf(f,"go\n");
	    fclose(f);
	} else {
	    fname = p2plast[pl]->tsg_plotfile;
	    if (debug)
		fprintf(stderr,"Removing incomplete plot file '%s'\n",
			fname);
	    fclose(f);
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
	   xp_timestamp(t1), x1,
	   xp_timestamp(t2), x2);
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
           xp_timestamp(t1), x1,
           xp_timestamp(t2), x2);
}


void
plotter_diamond(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"diamond %s %u", xp_timestamp(t), x);
}


void
plotter_dot(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"dot %s %u", xp_timestamp(t), x);
}


void
plotter_plus(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"plus %s %u", xp_timestamp(t), x);
}


void
plotter_box(
    PLOTTER pl,
    struct timeval	t,
    u_long		x)
{
    DoPlot(pl,"box %s %u", xp_timestamp(t), x);
}



void
plotter_arrow(
    PLOTTER pl,
    struct timeval	t,
    u_long		x,
    char	dir)
{
    DoPlot(pl,"%carrow %s %u", dir, xp_timestamp(t), x);
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
    DoPlot(pl,"%ctick %s %u", dir, xp_timestamp(t), x);
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



void
plotter_text(
    PLOTTER pl,
    struct timeval	t,
    u_long		x,
    char		*where,
    char		*str)
{
    DoPlot(pl,"%stext %s %u\n%s", where, xp_timestamp(t), x, str);
}
