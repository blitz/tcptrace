#
# Gnu Makefile for tcptrace
#

SUPPORTED_FORMATS = -DGROK_SNOOP -DGROK_TCPDUMP -DGROK_NETM

OPTIM = -O2 -g -Wall
#
INCS=-I/usr/local/include
CFLAGS = ${OPTIM} ${INCS} ${SUPPORTED_FORMATS}
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
	LDLIBS = -lpcap -lnsl -lsocket -lucb -lelf -lm
else
# SunOS (I hope)
	LDLIBS = -lpcap -lm
endif


OFILES= gcache.o main.o names.o netm.o output.o plotter.o print.o \
	rtt.o snoop.o tcpdump.o trace.o

tcptrace: ${OFILES}
	${CC} ${LDFLAGS} ${CFLAGS} ${OFILES} -o tcptrace ${LDLIBS}

install: tcptrace
	install -s tcptrace /usr/local/bin/tcptrace

ci:
	ci -q -l -t-initial -mlatest Makefile *.h *.c

clean:
	rm -f *.o tcptrace core [a-z]2[a-z] [a-z][a-z]2[a-z][a-z] *.PS.?

tidy:
	rm -f core [a-z]2[a-z] [a-z][a-z]2[a-z][a-z] *.PS.?

depend:
#	mkdep *.c
	makedepend ${INCS} -w 10 *.c
# DO NOT DELETE

gcache.o: /usr/include/sys/types.h
gcache.o: /usr/include/sys/machtypes.h
gcache.o: /usr/include/sys/select.h
gcache.o: /usr/include/sys/time.h
gcache.o: /usr/include/sys/time.h
gcache.o: tcptrace.h
gcache.o: /usr/include/stdio.h
gcache.o: /usr/include/string.h
gcache.o: /usr/include/unistd.h
gcache.o: /usr/include/sys/unistd.h
gcache.o: /usr/include/sys/socket.h
gcache.o: /usr/include/sys/netconfig.h
gcache.o: /usr/include/net/if.h
gcache.o: /usr/include/netinet/in.h
gcache.o: /usr/include/sys/stream.h
gcache.o: /usr/include/sys/vnode.h
gcache.o: /usr/include/sys/t_lock.h
gcache.o: /usr/include/sys/machlock.h
gcache.o: /usr/include/sys/dki_lkinfo.h
gcache.o: /usr/include/sys/dl.h
gcache.o: /usr/include/sys/sleepq.h
gcache.o: /usr/include/sys/turnstile.h
gcache.o: /usr/include/sys/param.h
gcache.o: /usr/include/sys/pirec.h
gcache.o: /usr/include/sys/mutex.h
gcache.o: /usr/include/sys/cred.h
gcache.o: /usr/include/sys/uio.h
gcache.o: /usr/include/sys/poll.h
gcache.o: /usr/include/sys/strmdep.h
gcache.o: /usr/include/sys/byteorder.h
gcache.o: /usr/include/netinet/in_systm.h
gcache.o: /usr/include/arpa/inet.h
gcache.o: /usr/include/netinet/if_ether.h
gcache.o: /usr/include/net/if_arp.h
gcache.o: /usr/include/netinet/ip.h
gcache.o: /usr/include/netinet/tcp.h
gcache.o: /usr/include/netdb.h
gcache.o: gcache.h
main.o: tcptrace.h
main.o: /usr/include/stdio.h
main.o: /usr/include/string.h
main.o: /usr/include/sys/types.h
main.o: /usr/include/sys/machtypes.h
main.o: /usr/include/sys/select.h
main.o: /usr/include/sys/time.h
main.o: /usr/include/sys/time.h
main.o: /usr/include/unistd.h
main.o: /usr/include/sys/unistd.h
main.o: /usr/include/sys/socket.h
main.o: /usr/include/sys/netconfig.h
main.o: /usr/include/net/if.h
main.o: /usr/include/netinet/in.h
main.o: /usr/include/sys/stream.h
main.o: /usr/include/sys/vnode.h
main.o: /usr/include/sys/t_lock.h
main.o: /usr/include/sys/machlock.h
main.o: /usr/include/sys/dki_lkinfo.h
main.o: /usr/include/sys/dl.h
main.o: /usr/include/sys/sleepq.h
main.o: /usr/include/sys/turnstile.h
main.o: /usr/include/sys/param.h
main.o: /usr/include/sys/pirec.h
main.o: /usr/include/sys/mutex.h
main.o: /usr/include/sys/cred.h
main.o: /usr/include/sys/uio.h
main.o: /usr/include/sys/poll.h
main.o: /usr/include/sys/strmdep.h
main.o: /usr/include/sys/byteorder.h
main.o: /usr/include/netinet/in_systm.h
main.o: /usr/include/arpa/inet.h
main.o: /usr/include/netinet/if_ether.h
main.o: /usr/include/net/if_arp.h
main.o: /usr/include/netinet/ip.h
main.o: /usr/include/netinet/tcp.h
main.o: /usr/include/netdb.h
main.o: file_formats.h
names.o: tcptrace.h
names.o: /usr/include/stdio.h
names.o: /usr/include/string.h
names.o: /usr/include/sys/types.h
names.o: /usr/include/sys/machtypes.h
names.o: /usr/include/sys/select.h
names.o: /usr/include/sys/time.h
names.o: /usr/include/sys/time.h
names.o: /usr/include/unistd.h
names.o: /usr/include/sys/unistd.h
names.o: /usr/include/sys/socket.h
names.o: /usr/include/sys/netconfig.h
names.o: /usr/include/net/if.h
names.o: /usr/include/netinet/in.h
names.o: /usr/include/sys/stream.h
names.o: /usr/include/sys/vnode.h
names.o: /usr/include/sys/t_lock.h
names.o: /usr/include/sys/machlock.h
names.o: /usr/include/sys/dki_lkinfo.h
names.o: /usr/include/sys/dl.h
names.o: /usr/include/sys/sleepq.h
names.o: /usr/include/sys/turnstile.h
names.o: /usr/include/sys/param.h
names.o: /usr/include/sys/pirec.h
names.o: /usr/include/sys/mutex.h
names.o: /usr/include/sys/cred.h
names.o: /usr/include/sys/uio.h
names.o: /usr/include/sys/poll.h
names.o: /usr/include/sys/strmdep.h
names.o: /usr/include/sys/byteorder.h
names.o: /usr/include/netinet/in_systm.h
names.o: /usr/include/arpa/inet.h
names.o: /usr/include/netinet/if_ether.h
names.o: /usr/include/net/if_arp.h
names.o: /usr/include/netinet/ip.h
names.o: /usr/include/netinet/tcp.h
names.o: /usr/include/netdb.h
names.o: gcache.h
output.o: tcptrace.h
output.o: /usr/include/stdio.h
output.o: /usr/include/string.h
output.o: /usr/include/sys/types.h
output.o: /usr/include/sys/machtypes.h
output.o: /usr/include/sys/select.h
output.o: /usr/include/sys/time.h
output.o: /usr/include/sys/time.h
output.o: /usr/include/unistd.h
output.o: /usr/include/sys/unistd.h
output.o: /usr/include/sys/socket.h
output.o: /usr/include/sys/netconfig.h
output.o: /usr/include/net/if.h
output.o: /usr/include/netinet/in.h
output.o: /usr/include/sys/stream.h
output.o: /usr/include/sys/vnode.h
output.o: /usr/include/sys/t_lock.h
output.o: /usr/include/sys/machlock.h
output.o: /usr/include/sys/dki_lkinfo.h
output.o: /usr/include/sys/dl.h
output.o: /usr/include/sys/sleepq.h
output.o: /usr/include/sys/turnstile.h
output.o: /usr/include/sys/param.h
output.o: /usr/include/sys/pirec.h
output.o: /usr/include/sys/mutex.h
output.o: /usr/include/sys/cred.h
output.o: /usr/include/sys/uio.h
output.o: /usr/include/sys/poll.h
output.o: /usr/include/sys/strmdep.h
output.o: /usr/include/sys/byteorder.h
output.o: /usr/include/netinet/in_systm.h
output.o: /usr/include/arpa/inet.h
output.o: /usr/include/netinet/if_ether.h
output.o: /usr/include/net/if_arp.h
output.o: /usr/include/netinet/ip.h
output.o: /usr/include/netinet/tcp.h
output.o: /usr/include/netdb.h
output.o: gcache.h
output.o: /usr/local/include/math.h
output.o: /usr/local/include/_ansi.h
output.o: /usr/local/include/sys/config.h
plotter.o: tcptrace.h
plotter.o: /usr/include/stdio.h
plotter.o: /usr/include/string.h
plotter.o: /usr/include/sys/types.h
plotter.o: /usr/include/sys/machtypes.h
plotter.o: /usr/include/sys/select.h
plotter.o: /usr/include/sys/time.h
plotter.o: /usr/include/sys/time.h
plotter.o: /usr/include/unistd.h
plotter.o: /usr/include/sys/unistd.h
plotter.o: /usr/include/sys/socket.h
plotter.o: /usr/include/sys/netconfig.h
plotter.o: /usr/include/net/if.h
plotter.o: /usr/include/netinet/in.h
plotter.o: /usr/include/sys/stream.h
plotter.o: /usr/include/sys/vnode.h
plotter.o: /usr/include/sys/t_lock.h
plotter.o: /usr/include/sys/machlock.h
plotter.o: /usr/include/sys/dki_lkinfo.h
plotter.o: /usr/include/sys/dl.h
plotter.o: /usr/include/sys/sleepq.h
plotter.o: /usr/include/sys/turnstile.h
plotter.o: /usr/include/sys/param.h
plotter.o: /usr/include/sys/pirec.h
plotter.o: /usr/include/sys/mutex.h
plotter.o: /usr/include/sys/cred.h
plotter.o: /usr/include/sys/uio.h
plotter.o: /usr/include/sys/poll.h
plotter.o: /usr/include/sys/strmdep.h
plotter.o: /usr/include/sys/byteorder.h
plotter.o: /usr/include/netinet/in_systm.h
plotter.o: /usr/include/arpa/inet.h
plotter.o: /usr/include/netinet/if_ether.h
plotter.o: /usr/include/net/if_arp.h
plotter.o: /usr/include/netinet/ip.h
plotter.o: /usr/include/netinet/tcp.h
plotter.o: /usr/include/netdb.h
plotter.o: /usr/include/stdarg.h
print.o: tcptrace.h
print.o: /usr/include/stdio.h
print.o: /usr/include/string.h
print.o: /usr/include/sys/types.h
print.o: /usr/include/sys/machtypes.h
print.o: /usr/include/sys/select.h
print.o: /usr/include/sys/time.h
print.o: /usr/include/sys/time.h
print.o: /usr/include/unistd.h
print.o: /usr/include/sys/unistd.h
print.o: /usr/include/sys/socket.h
print.o: /usr/include/sys/netconfig.h
print.o: /usr/include/net/if.h
print.o: /usr/include/netinet/in.h
print.o: /usr/include/sys/stream.h
print.o: /usr/include/sys/vnode.h
print.o: /usr/include/sys/t_lock.h
print.o: /usr/include/sys/machlock.h
print.o: /usr/include/sys/dki_lkinfo.h
print.o: /usr/include/sys/dl.h
print.o: /usr/include/sys/sleepq.h
print.o: /usr/include/sys/turnstile.h
print.o: /usr/include/sys/param.h
print.o: /usr/include/sys/pirec.h
print.o: /usr/include/sys/mutex.h
print.o: /usr/include/sys/cred.h
print.o: /usr/include/sys/uio.h
print.o: /usr/include/sys/poll.h
print.o: /usr/include/sys/strmdep.h
print.o: /usr/include/sys/byteorder.h
print.o: /usr/include/netinet/in_systm.h
print.o: /usr/include/arpa/inet.h
print.o: /usr/include/netinet/if_ether.h
print.o: /usr/include/net/if_arp.h
print.o: /usr/include/netinet/ip.h
print.o: /usr/include/netinet/tcp.h
print.o: /usr/include/netdb.h
rtt.o: tcptrace.h
rtt.o: /usr/include/stdio.h
rtt.o: /usr/include/string.h
rtt.o: /usr/include/sys/types.h
rtt.o: /usr/include/sys/machtypes.h
rtt.o: /usr/include/sys/select.h
rtt.o: /usr/include/sys/time.h
rtt.o: /usr/include/sys/time.h
rtt.o: /usr/include/unistd.h
rtt.o: /usr/include/sys/unistd.h
rtt.o: /usr/include/sys/socket.h
rtt.o: /usr/include/sys/netconfig.h
rtt.o: /usr/include/net/if.h
rtt.o: /usr/include/netinet/in.h
rtt.o: /usr/include/sys/stream.h
rtt.o: /usr/include/sys/vnode.h
rtt.o: /usr/include/sys/t_lock.h
rtt.o: /usr/include/sys/machlock.h
rtt.o: /usr/include/sys/dki_lkinfo.h
rtt.o: /usr/include/sys/dl.h
rtt.o: /usr/include/sys/sleepq.h
rtt.o: /usr/include/sys/turnstile.h
rtt.o: /usr/include/sys/param.h
rtt.o: /usr/include/sys/pirec.h
rtt.o: /usr/include/sys/mutex.h
rtt.o: /usr/include/sys/cred.h
rtt.o: /usr/include/sys/uio.h
rtt.o: /usr/include/sys/poll.h
rtt.o: /usr/include/sys/strmdep.h
rtt.o: /usr/include/sys/byteorder.h
rtt.o: /usr/include/netinet/in_systm.h
rtt.o: /usr/include/arpa/inet.h
rtt.o: /usr/include/netinet/if_ether.h
rtt.o: /usr/include/net/if_arp.h
rtt.o: /usr/include/netinet/ip.h
rtt.o: /usr/include/netinet/tcp.h
rtt.o: /usr/include/netdb.h
trace.o: tcptrace.h
trace.o: /usr/include/stdio.h
trace.o: /usr/include/string.h
trace.o: /usr/include/sys/types.h
trace.o: /usr/include/sys/machtypes.h
trace.o: /usr/include/sys/select.h
trace.o: /usr/include/sys/time.h
trace.o: /usr/include/sys/time.h
trace.o: /usr/include/unistd.h
trace.o: /usr/include/sys/unistd.h
trace.o: /usr/include/sys/socket.h
trace.o: /usr/include/sys/netconfig.h
trace.o: /usr/include/net/if.h
trace.o: /usr/include/netinet/in.h
trace.o: /usr/include/sys/stream.h
trace.o: /usr/include/sys/vnode.h
trace.o: /usr/include/sys/t_lock.h
trace.o: /usr/include/sys/machlock.h
trace.o: /usr/include/sys/dki_lkinfo.h
trace.o: /usr/include/sys/dl.h
trace.o: /usr/include/sys/sleepq.h
trace.o: /usr/include/sys/turnstile.h
trace.o: /usr/include/sys/param.h
trace.o: /usr/include/sys/pirec.h
trace.o: /usr/include/sys/mutex.h
trace.o: /usr/include/sys/cred.h
trace.o: /usr/include/sys/uio.h
trace.o: /usr/include/sys/poll.h
trace.o: /usr/include/sys/strmdep.h
trace.o: /usr/include/sys/byteorder.h
trace.o: /usr/include/netinet/in_systm.h
trace.o: /usr/include/arpa/inet.h
trace.o: /usr/include/netinet/if_ether.h
trace.o: /usr/include/net/if_arp.h
trace.o: /usr/include/netinet/ip.h
trace.o: /usr/include/netinet/tcp.h
trace.o: /usr/include/netdb.h
trace.o: gcache.h
