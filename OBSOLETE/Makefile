#
# Gnu Makefile for tcptrace
#

OPTIM = -O
OPTIM = -O2
OPTIM = -O2 -Wall -pg
OPTIM = -O2 -g -pg
OPTIM = -g
OPTIM = -g -Wall -pg
OPTIM = -g -Wall
OPTIM = -g -Wall
OPTIM = -O2 -Wall
OPTIM = -O2
#
INCS=-I/usr/local/include
CFLAGS = ${OPTIM} ${INCS}
#
CC=gcc
#
CPPFLAGS = 
LDFLAGS = -L/usr/local/lib

#
# All the different libraries, differ from machine to machine
#
ifeq ($(wildcard /./vmunix),)
# Solaris
	LDLIBS = -lpcap -lnsl -lsocket -lucb -lelf
else
# SunOS (I hope)
	LDLIBS = -lpcap
endif


OFILES= gcache.o main.o names.o netm.o plotter.o print.o \
	snoop.o tcpdump.o trace.o

tcptrace: ${OFILES}
	${CC} ${LDFLAGS} ${CFLAGS} ${OFILES} -o tcptrace ${LDLIBS}

install: tcptrace
	install -s tcptrace /usr/local/bin/tcptrace

clean:
	rm -f *.o tcptrace core [a-z]2[a-z] [a-z][a-z]2[a-z][a-z] *.PS.?

tidy:
	rm -f core [a-z]2[a-z] [a-z][a-z]2[a-z][a-z] *.PS.?

depend:
#	mkdep *.c
	makedepend ${INCS} -w 10 *.c
# DO NOT DELETE THIS LINE -- make depend depends on it.

gcache.o: tcptrace.h
gcache.o: gcache.h
main.o: tcptrace.h
names.o: tcptrace.h
names.o: gcache.h
netm.o: tcptrace.h
netm.o: netm.h
plotter.o: tcptrace.h
print.o: tcptrace.h
snoop.o: tcptrace.h
snoop.o: snoop.h
tcpdump.o: /usr/local/include/pcap.h
tcpdump.o: /usr/local/include/net/bpf.h
tcpdump.o: tcptrace.h
trace.o: tcptrace.h
trace.o: gcache.h
