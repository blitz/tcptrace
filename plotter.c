#include "tcptrace.h"
#include <varargs.h>

#define MAX_PLOTTERS (2*MAX_TCP_PAIRS)



static FILE *fplot[MAX_PLOTTERS] = {NULL};
static tcp_pair *p2ptp[MAX_PLOTTERS] = {NULL};
static PLOTTER plotter_ix = -1;


#define PLOT if(plotem) DoPlot



char *PlotName(pl)
     PLOTTER pl;
{
	static char filename[10];

	if ((pl % 2) == 0)
	    sprintf(filename,"%c2%c", 'a' + pl, 'a' + pl + 1);
	else
	    sprintf(filename,"%c2%c", 'a' + pl, 'a' + pl - 1);

	return(filename);
}



static void DoPlot(pl, fmt, va_alist)
     PLOTTER	pl;
     char	*fmt;
     va_dcl
{
	va_list	ap;
	FILE *f = NULL;

	va_start(ap);

	if (pl > plotter_ix) {
		fprintf(stderr,"Illegal plotter: %d\n", pl);
		exit(-1);
	}

	f = fplot[pl];

	vfprintf(f,fmt,ap);
	fprintf (f,"\n");

	va_end(ap);

	return;
}


int
plotter_init(ptp,title)
     tcp_pair *ptp;
     char *title;
{
	PLOTTER pl;
	FILE *f;
	char *filename;

	++plotter_ix;
	if (plotter_ix >= MAX_PLOTTERS) {
		fprintf(stderr,"No more plotters\n");
		exit(-1);
	}

	pl = plotter_ix;

	filename = PlotName(pl);

	if (debug)
	    fprintf(stderr,"Plotter %d file is '%s'\n", pl, filename);

	if ((f = fopen(filename,"w")) == NULL) {
		perror(filename);
		exit(-2);
	}

	fprintf(f,"timeval unsigned\n");
	fprintf(f,"title\n%s\n", title);

	fplot[pl] = f;
	p2ptp[pl] = ptp;
	return(pl);
}


void
plotter_done()
{
	PLOTTER pl;
	FILE *f;
	char *fname;

	for (pl = 0; pl < plotter_ix; ++pl) {
		f = fplot[pl];
		if (!ignore_non_comp || Complete(p2ptp[pl])) {
			fprintf(f,"go\n");
			fclose(f);
		} else {
			fname = PlotName(pl);
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
plotter_line(pl,t1,x1,t2,x2)
     PLOTTER pl;
     struct timeval	t1,t2;
     unsigned long	x1,x2;
{
	PLOT(pl,"line %u.%06u %u %u.%06u %u",
	     t1.tv_sec, t1.tv_usec,
	     x1,
	     t2.tv_sec, t2.tv_usec,
	     x2);
}


void
plotter_darrow(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	PLOT(pl,"darrow %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_uarrow(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	PLOT(pl,"uarrow %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_dtick(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	PLOT(pl,"dtick %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_utick(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	PLOT(pl,"utick %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_text(pl,t,x,where,str)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
     char		*where;
     char		*str;
{
	PLOT(pl,"%stext %u.%06u %u\n%s",
	     where,
	     t.tv_sec, t.tv_usec,x,
	     str);
}


