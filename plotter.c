#include "tcptrace.h"
#include <varargs.h>


int max_plotters;


static FILE **fplot;
static struct last **p2plast;
static PLOTTER plotter_ix = NO_PLOTTER;



void plot_init()
{
	max_plotters = 2*max_tcp_pairs;

	fplot = (FILE **) malloc(max_plotters * sizeof(FILE *));
	if (!fplot) {
		perror("fplot malloc");
		exit(-1);
	}

	p2plast = (struct last **) malloc(max_plotters * sizeof(struct last *));
	if (!p2plast) {
		perror("p2plast malloc");
		exit(-1);
	}
	bzero(fplot,  max_plotters * sizeof(FILE *));
	bzero(p2plast,max_plotters * sizeof(struct last *));
}



char *HostLetter(ix)
     u_int ix;
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



char *PlotName(plast,pl)
     struct last *plast;
     PLOTTER pl;
{
	static char filename[10];

	sprintf(filename,"%s2%s",
		plast->host_letter, plast->ptwin->host_letter);

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

	vfprintf(f,fmt,ap);
	fprintf (f,"\n");

	va_end(ap);

	return;
}


int
new_plotter(plast,title)
     struct last *plast;
     char *title;
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

	filename = PlotName(plast,pl);

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
	plast->plotfile = strdup(filename);
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
		if (!ignore_non_comp || Complete(p2plast[pl]->ptp)) {
			fprintf(f,"go\n");
			fclose(f);
		} else {
			fname = p2plast[pl]->plotfile;
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
	DoPlot(pl,"line %u.%06u %u %u.%06u %u",
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
	DoPlot(pl,"darrow %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_uarrow(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	DoPlot(pl,"uarrow %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_dtick(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	DoPlot(pl,"dtick %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_utick(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	DoPlot(pl,"utick %u.%06u %u",
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
	DoPlot(pl,"%stext %u.%06u %u\n%s",
	     where,
	     t.tv_sec, t.tv_usec,x,
	     str);
}
