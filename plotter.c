#include "tcptrace.h"
#include <varargs.h>


PLOTTER abpl = 1;
PLOTTER bapl = 2;

FILE *fab = NULL;
FILE *fba = NULL;

static void plot(pl, fmt, va_alist)
     PLOTTER	pl;
     char	*fmt;
     va_dcl
{
	va_list	ap;
	FILE *f = NULL;

	va_start(ap);

	if (pl == abpl) {
		f = fab;
	} else if (pl == bapl) {
		f = fba;
	} else {
		fprintf(stderr,"Bad plotter: %d\n", pl);
		exit(-1);
	}

	vfprintf(f,fmt,ap);
	fprintf (f,"\n");

	va_end(ap);

	return;
}


void
plotter_init(pl,title)
     PLOTTER pl;
     char *title;
{
	if (pl == abpl) {
		if ((fab = fopen("a2b","w")) == NULL) {
			perror("a2b");
			exit(-2);
		}
		fprintf(fab,"timeval unsigned\n");
		fprintf(fab,"title\n%s\n", title);
	} else if (pl == bapl) {
		if ((fba = fopen("b2a","w")) == NULL) {
			perror("b2a");
			exit(-2);
		}
		fprintf(fba,"timeval unsigned\n");
		fprintf(fba,"title\n%s\n", title);
	} else {
		fprintf(stderr,"Bad plotter: %d\n", pl);
		exit(-1);
	}
}


void
plotter_done()
{
	if (fab != NULL) {
		fprintf(fab,"go\n");
		fclose(fab);
	}
	if (fba != NULL) {
		fprintf(fba,"go\n");
		fclose(fba);
	}
}



void
plotter_line(pl,t1,x1,t2,x2)
     PLOTTER pl;
     struct timeval	t1,t2;
     unsigned long	x1,x2;
{
	plot(pl,"line %u.%06u %u %u.%06u %u",
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
	plot(pl,"darrow %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_uarrow(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	plot(pl,"uarrow %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_dtick(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	plot(pl,"dtick %u.%06u %u",
	     t.tv_sec, t.tv_usec,x);
}


void
plotter_utick(pl,t,x)
     PLOTTER pl;
     struct timeval	t;
     unsigned long	x;
{
	plot(pl,"utick %u.%06u %u",
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
	plot(pl,"%stext %u.%06u %u\n%s",
	     where,
	     t.tv_sec, t.tv_usec,x,
	     str);
}


