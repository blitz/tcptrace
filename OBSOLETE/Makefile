#
# Gnu Makefile for tcptrace
#



#
# User-configurable constants
#
OPTIM	= -O2 -g -Wall
OPTIM	= -pg -O2 -g -Wall
INCS	= -I/usr/local/include
CC	= gcc
LDFLAGS = -L/usr/local/lib
SUPPORTED_FORMATS = -DGROK_SNOOP -DGROK_TCPDUMP -DGROK_NETM


#
# Standard rules
#
GCC_FLAGS = -finline-functions
CFLAGS	= ${OPTIM} ${INCS} ${SUPPORTED_FORMATS} ${GCC_FLAGS}


#
# All the different libraries, differ from machine to machine
#
ifeq ($(wildcard /./vmunix),)
# Solaris
	LDLIBS = -lpcap -lnsl -lsocket -lucb -lelf -lm
else
# SunOS (I hope)
	LDLIBS = -lpcap -lm
endif


OFILES= gcache.o main.o names.o netm.o output.o plotter.o print.o \
	rtt.o snoop.o tcpdump.o trace.o rexmit.o

tcptrace: ${OFILES}
	${CC} ${LDFLAGS} ${CFLAGS} ${OFILES} -o tcptrace ${LDLIBS}

install: tcptrace
	install -s tcptrace /usr/local/bin/tcptrace

ci:
	ci -q -l -t-initial -mlatest Makefile *.h *.c

clean:
	rm -f *.o tcptrace core *.xpl *.PS.?

tidy:
	rm -f core [a-z]2[a-z].xpl [a-z][a-z]2[a-z][a-z].xpl *.PS.?

depend:
#	mkdep *.c
	makedepend ${INCS} -w 10 *.c
# DO NOT DELETE

gcache.o: tcptrace.h
gcache.o: gcache.h
main.o: tcptrace.h
main.o: file_formats.h
names.o: tcptrace.h
names.o: gcache.h
output.o: tcptrace.h
output.o: gcache.h
plotter.o: tcptrace.h
print.o: tcptrace.h
rtt.o: tcptrace.h
trace.o: tcptrace.h
trace.o: gcache.h
