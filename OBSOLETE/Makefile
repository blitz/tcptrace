#
# Gnu Makefile for tcptrace
#



#
# User-configurable constants
#
OPTIM	= -pg -O2 -g -Wall
OPTIM	= -O2 -g -Wall
INCS	= -I/usr/local/include
CC	= gcc
LDFLAGS = -L/usr/local/lib
SUPPORTED_FORMATS = -DGROK_SNOOP -DGROK_TCPDUMP -DGROK_NETM -DGROK_EP


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


OFILES= etherpeek.o gcache.o tcptrace.o mfiles.o names.o netm.o output.o \
	plotter.o print.o snoop.o tcpdump.o thruput.o trace.o rexmit.o 

tcptrace: ${OFILES}
	${CC} ${LDFLAGS} ${CFLAGS} ${OFILES} -o tcptrace ${LDLIBS}

install: tcptrace
	install -s tcptrace /usr/local/bin/tcptrace

ci:
	ci -u -q -t-initial -mlatest Makefile *.h *.c

clean:
	rm -f *.o tcptrace core *.xpl *.rtt *.tput *.PS.?

tidy:
	rm -f core *2*.xpl *2*.rtt *2*.tput *.PS.?

noplots:
	rm -f *2*.xpl *2*.rtt *2*.rttraw *2*.tput *.PS.?

depend:
#	mkdep *.c
	makedepend ${INCS} -w 10 *.c
# DO NOT DELETE

gcache.o: gcache.h
gcache.o: tcptrace.h
tcptrace.o: file_formats.h
tcptrace.o: tcptrace.h
names.o: gcache.h
names.o: tcptrace.h
output.o: gcache.h
output.o: tcptrace.h
plotter.o: tcptrace.h
print.o: tcptrace.h
rexmit.o: tcptrace.h
trace.o: gcache.h
trace.o: tcptrace.h
# DO NOT DELETE THIS LINE -- make depend depends on it.

gcache.o: /usr/include/sys/types.h
gcache.o: /usr/include/sys/feature_tests.h
gcache.o: /usr/include/sys/machtypes.h
gcache.o: /usr/include/sys/isa_defs.h
gcache.o: tcptrace.h
gcache.o: /usr/include/stdio.h
gcache.o: /usr/include/string.h
gcache.o: /usr/include/unistd.h
gcache.o: /usr/include/sys/unistd.h
gcache.o: /usr/include/sys/time.h
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
gcache.o: /usr/include/sys/rwlock.h
gcache.o: /usr/include/sys/semaphore.h
gcache.o: /usr/include/sys/condvar.h
gcache.o: /usr/include/sys/cred.h
gcache.o: /usr/include/sys/uio.h
gcache.o: /usr/include/vm/seg_enum.h
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
gcache.o: /usr/include/ctype.h
gcache.o: /usr/include/signal.h
gcache.o: /usr/include/sys/signal.h
gcache.o: /usr/include/sys/stat.h
gcache.o: /usr/include/stdarg.h
gcache.o: /usr/include/varargs.h
gcache.o: gcache.h
mfiles.o: tcptrace.h
mfiles.o: /usr/include/stdio.h
mfiles.o: /usr/include/sys/feature_tests.h
mfiles.o: /usr/include/string.h
mfiles.o: /usr/include/sys/types.h
mfiles.o: /usr/include/sys/machtypes.h
mfiles.o: /usr/include/sys/isa_defs.h
mfiles.o: /usr/include/unistd.h
mfiles.o: /usr/include/sys/unistd.h
mfiles.o: /usr/include/sys/time.h
mfiles.o: /usr/include/sys/socket.h
mfiles.o: /usr/include/sys/netconfig.h
mfiles.o: /usr/include/net/if.h
mfiles.o: /usr/include/netinet/in.h
mfiles.o: /usr/include/sys/stream.h
mfiles.o: /usr/include/sys/vnode.h
mfiles.o: /usr/include/sys/t_lock.h
mfiles.o: /usr/include/sys/machlock.h
mfiles.o: /usr/include/sys/dki_lkinfo.h
mfiles.o: /usr/include/sys/dl.h
mfiles.o: /usr/include/sys/sleepq.h
mfiles.o: /usr/include/sys/turnstile.h
mfiles.o: /usr/include/sys/param.h
mfiles.o: /usr/include/sys/pirec.h
mfiles.o: /usr/include/sys/mutex.h
mfiles.o: /usr/include/sys/rwlock.h
mfiles.o: /usr/include/sys/semaphore.h
mfiles.o: /usr/include/sys/condvar.h
mfiles.o: /usr/include/sys/cred.h
mfiles.o: /usr/include/sys/uio.h
mfiles.o: /usr/include/vm/seg_enum.h
mfiles.o: /usr/include/sys/poll.h
mfiles.o: /usr/include/sys/strmdep.h
mfiles.o: /usr/include/sys/byteorder.h
mfiles.o: /usr/include/netinet/in_systm.h
mfiles.o: /usr/include/arpa/inet.h
mfiles.o: /usr/include/netinet/if_ether.h
mfiles.o: /usr/include/net/if_arp.h
mfiles.o: /usr/include/netinet/ip.h
mfiles.o: /usr/include/netinet/tcp.h
mfiles.o: /usr/include/netdb.h
mfiles.o: /usr/include/ctype.h
mfiles.o: /usr/include/signal.h
mfiles.o: /usr/include/sys/signal.h
mfiles.o: /usr/include/sys/stat.h
mfiles.o: /usr/include/stdarg.h
mfiles.o: /usr/include/varargs.h
mfiles.o: /usr/include/errno.h
mfiles.o: /usr/include/sys/errno.h
names.o: tcptrace.h
names.o: /usr/include/stdio.h
names.o: /usr/include/sys/feature_tests.h
names.o: /usr/include/string.h
names.o: /usr/include/sys/types.h
names.o: /usr/include/sys/machtypes.h
names.o: /usr/include/sys/isa_defs.h
names.o: /usr/include/unistd.h
names.o: /usr/include/sys/unistd.h
names.o: /usr/include/sys/time.h
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
names.o: /usr/include/sys/rwlock.h
names.o: /usr/include/sys/semaphore.h
names.o: /usr/include/sys/condvar.h
names.o: /usr/include/sys/cred.h
names.o: /usr/include/sys/uio.h
names.o: /usr/include/vm/seg_enum.h
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
names.o: /usr/include/ctype.h
names.o: /usr/include/signal.h
names.o: /usr/include/sys/signal.h
names.o: /usr/include/sys/stat.h
names.o: /usr/include/stdarg.h
names.o: /usr/include/varargs.h
names.o: gcache.h
output.o: tcptrace.h
output.o: /usr/include/stdio.h
output.o: /usr/include/sys/feature_tests.h
output.o: /usr/include/string.h
output.o: /usr/include/sys/types.h
output.o: /usr/include/sys/machtypes.h
output.o: /usr/include/sys/isa_defs.h
output.o: /usr/include/unistd.h
output.o: /usr/include/sys/unistd.h
output.o: /usr/include/sys/time.h
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
output.o: /usr/include/sys/rwlock.h
output.o: /usr/include/sys/semaphore.h
output.o: /usr/include/sys/condvar.h
output.o: /usr/include/sys/cred.h
output.o: /usr/include/sys/uio.h
output.o: /usr/include/vm/seg_enum.h
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
output.o: /usr/include/ctype.h
output.o: /usr/include/signal.h
output.o: /usr/include/sys/signal.h
output.o: /usr/include/sys/stat.h
output.o: /usr/include/stdarg.h
output.o: /usr/include/varargs.h
output.o: gcache.h
output.o: /usr/local/include/math.h
output.o: /usr/local/include/_ansi.h
output.o: /usr/local/include/sys/config.h
plotter.o: tcptrace.h
plotter.o: /usr/include/stdio.h
plotter.o: /usr/include/sys/feature_tests.h
plotter.o: /usr/include/string.h
plotter.o: /usr/include/sys/types.h
plotter.o: /usr/include/sys/machtypes.h
plotter.o: /usr/include/sys/isa_defs.h
plotter.o: /usr/include/unistd.h
plotter.o: /usr/include/sys/unistd.h
plotter.o: /usr/include/sys/time.h
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
plotter.o: /usr/include/sys/rwlock.h
plotter.o: /usr/include/sys/semaphore.h
plotter.o: /usr/include/sys/condvar.h
plotter.o: /usr/include/sys/cred.h
plotter.o: /usr/include/sys/uio.h
plotter.o: /usr/include/vm/seg_enum.h
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
plotter.o: /usr/include/ctype.h
plotter.o: /usr/include/signal.h
plotter.o: /usr/include/sys/signal.h
plotter.o: /usr/include/sys/stat.h
plotter.o: /usr/include/stdarg.h
plotter.o: /usr/include/varargs.h
print.o: tcptrace.h
print.o: /usr/include/stdio.h
print.o: /usr/include/sys/feature_tests.h
print.o: /usr/include/string.h
print.o: /usr/include/sys/types.h
print.o: /usr/include/sys/machtypes.h
print.o: /usr/include/sys/isa_defs.h
print.o: /usr/include/unistd.h
print.o: /usr/include/sys/unistd.h
print.o: /usr/include/sys/time.h
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
print.o: /usr/include/sys/rwlock.h
print.o: /usr/include/sys/semaphore.h
print.o: /usr/include/sys/condvar.h
print.o: /usr/include/sys/cred.h
print.o: /usr/include/sys/uio.h
print.o: /usr/include/vm/seg_enum.h
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
print.o: /usr/include/ctype.h
print.o: /usr/include/signal.h
print.o: /usr/include/sys/signal.h
print.o: /usr/include/sys/stat.h
print.o: /usr/include/stdarg.h
print.o: /usr/include/varargs.h
rexmit.o: tcptrace.h
rexmit.o: /usr/include/stdio.h
rexmit.o: /usr/include/sys/feature_tests.h
rexmit.o: /usr/include/string.h
rexmit.o: /usr/include/sys/types.h
rexmit.o: /usr/include/sys/machtypes.h
rexmit.o: /usr/include/sys/isa_defs.h
rexmit.o: /usr/include/unistd.h
rexmit.o: /usr/include/sys/unistd.h
rexmit.o: /usr/include/sys/time.h
rexmit.o: /usr/include/sys/socket.h
rexmit.o: /usr/include/sys/netconfig.h
rexmit.o: /usr/include/net/if.h
rexmit.o: /usr/include/netinet/in.h
rexmit.o: /usr/include/sys/stream.h
rexmit.o: /usr/include/sys/vnode.h
rexmit.o: /usr/include/sys/t_lock.h
rexmit.o: /usr/include/sys/machlock.h
rexmit.o: /usr/include/sys/dki_lkinfo.h
rexmit.o: /usr/include/sys/dl.h
rexmit.o: /usr/include/sys/sleepq.h
rexmit.o: /usr/include/sys/turnstile.h
rexmit.o: /usr/include/sys/param.h
rexmit.o: /usr/include/sys/pirec.h
rexmit.o: /usr/include/sys/mutex.h
rexmit.o: /usr/include/sys/rwlock.h
rexmit.o: /usr/include/sys/semaphore.h
rexmit.o: /usr/include/sys/condvar.h
rexmit.o: /usr/include/sys/cred.h
rexmit.o: /usr/include/sys/uio.h
rexmit.o: /usr/include/vm/seg_enum.h
rexmit.o: /usr/include/sys/poll.h
rexmit.o: /usr/include/sys/strmdep.h
rexmit.o: /usr/include/sys/byteorder.h
rexmit.o: /usr/include/netinet/in_systm.h
rexmit.o: /usr/include/arpa/inet.h
rexmit.o: /usr/include/netinet/if_ether.h
rexmit.o: /usr/include/net/if_arp.h
rexmit.o: /usr/include/netinet/ip.h
rexmit.o: /usr/include/netinet/tcp.h
rexmit.o: /usr/include/netdb.h
rexmit.o: /usr/include/ctype.h
rexmit.o: /usr/include/signal.h
rexmit.o: /usr/include/sys/signal.h
rexmit.o: /usr/include/sys/stat.h
rexmit.o: /usr/include/stdarg.h
rexmit.o: /usr/include/varargs.h
rtt.o: tcptrace.h
rtt.o: /usr/include/stdio.h
rtt.o: /usr/include/sys/feature_tests.h
rtt.o: /usr/include/string.h
rtt.o: /usr/include/sys/types.h
rtt.o: /usr/include/sys/machtypes.h
rtt.o: /usr/include/sys/isa_defs.h
rtt.o: /usr/include/unistd.h
rtt.o: /usr/include/sys/unistd.h
rtt.o: /usr/include/sys/time.h
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
rtt.o: /usr/include/sys/rwlock.h
rtt.o: /usr/include/sys/semaphore.h
rtt.o: /usr/include/sys/condvar.h
rtt.o: /usr/include/sys/cred.h
rtt.o: /usr/include/sys/uio.h
rtt.o: /usr/include/vm/seg_enum.h
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
rtt.o: /usr/include/ctype.h
rtt.o: /usr/include/signal.h
rtt.o: /usr/include/sys/signal.h
rtt.o: /usr/include/sys/stat.h
rtt.o: /usr/include/stdarg.h
rtt.o: /usr/include/varargs.h
tcptrace.o: tcptrace.h
tcptrace.o: /usr/include/stdio.h
tcptrace.o: /usr/include/sys/feature_tests.h
tcptrace.o: /usr/include/string.h
tcptrace.o: /usr/include/sys/types.h
tcptrace.o: /usr/include/sys/machtypes.h
tcptrace.o: /usr/include/sys/isa_defs.h
tcptrace.o: /usr/include/unistd.h
tcptrace.o: /usr/include/sys/unistd.h
tcptrace.o: /usr/include/sys/time.h
tcptrace.o: /usr/include/sys/socket.h
tcptrace.o: /usr/include/sys/netconfig.h
tcptrace.o: /usr/include/net/if.h
tcptrace.o: /usr/include/netinet/in.h
tcptrace.o: /usr/include/sys/stream.h
tcptrace.o: /usr/include/sys/vnode.h
tcptrace.o: /usr/include/sys/t_lock.h
tcptrace.o: /usr/include/sys/machlock.h
tcptrace.o: /usr/include/sys/dki_lkinfo.h
tcptrace.o: /usr/include/sys/dl.h
tcptrace.o: /usr/include/sys/sleepq.h
tcptrace.o: /usr/include/sys/turnstile.h
tcptrace.o: /usr/include/sys/param.h
tcptrace.o: /usr/include/sys/pirec.h
tcptrace.o: /usr/include/sys/mutex.h
tcptrace.o: /usr/include/sys/rwlock.h
tcptrace.o: /usr/include/sys/semaphore.h
tcptrace.o: /usr/include/sys/condvar.h
tcptrace.o: /usr/include/sys/cred.h
tcptrace.o: /usr/include/sys/uio.h
tcptrace.o: /usr/include/vm/seg_enum.h
tcptrace.o: /usr/include/sys/poll.h
tcptrace.o: /usr/include/sys/strmdep.h
tcptrace.o: /usr/include/sys/byteorder.h
tcptrace.o: /usr/include/netinet/in_systm.h
tcptrace.o: /usr/include/arpa/inet.h
tcptrace.o: /usr/include/netinet/if_ether.h
tcptrace.o: /usr/include/net/if_arp.h
tcptrace.o: /usr/include/netinet/ip.h
tcptrace.o: /usr/include/netinet/tcp.h
tcptrace.o: /usr/include/netdb.h
tcptrace.o: /usr/include/ctype.h
tcptrace.o: /usr/include/signal.h
tcptrace.o: /usr/include/sys/signal.h
tcptrace.o: /usr/include/sys/stat.h
tcptrace.o: /usr/include/stdarg.h
tcptrace.o: /usr/include/varargs.h
tcptrace.o: file_formats.h
tcptrace.o: version.h
thruput.o: tcptrace.h
thruput.o: /usr/include/stdio.h
thruput.o: /usr/include/sys/feature_tests.h
thruput.o: /usr/include/string.h
thruput.o: /usr/include/sys/types.h
thruput.o: /usr/include/sys/machtypes.h
thruput.o: /usr/include/sys/isa_defs.h
thruput.o: /usr/include/unistd.h
thruput.o: /usr/include/sys/unistd.h
thruput.o: /usr/include/sys/time.h
thruput.o: /usr/include/sys/socket.h
thruput.o: /usr/include/sys/netconfig.h
thruput.o: /usr/include/net/if.h
thruput.o: /usr/include/netinet/in.h
thruput.o: /usr/include/sys/stream.h
thruput.o: /usr/include/sys/vnode.h
thruput.o: /usr/include/sys/t_lock.h
thruput.o: /usr/include/sys/machlock.h
thruput.o: /usr/include/sys/dki_lkinfo.h
thruput.o: /usr/include/sys/dl.h
thruput.o: /usr/include/sys/sleepq.h
thruput.o: /usr/include/sys/turnstile.h
thruput.o: /usr/include/sys/param.h
thruput.o: /usr/include/sys/pirec.h
thruput.o: /usr/include/sys/mutex.h
thruput.o: /usr/include/sys/rwlock.h
thruput.o: /usr/include/sys/semaphore.h
thruput.o: /usr/include/sys/condvar.h
thruput.o: /usr/include/sys/cred.h
thruput.o: /usr/include/sys/uio.h
thruput.o: /usr/include/vm/seg_enum.h
thruput.o: /usr/include/sys/poll.h
thruput.o: /usr/include/sys/strmdep.h
thruput.o: /usr/include/sys/byteorder.h
thruput.o: /usr/include/netinet/in_systm.h
thruput.o: /usr/include/arpa/inet.h
thruput.o: /usr/include/netinet/if_ether.h
thruput.o: /usr/include/net/if_arp.h
thruput.o: /usr/include/netinet/ip.h
thruput.o: /usr/include/netinet/tcp.h
thruput.o: /usr/include/netdb.h
thruput.o: /usr/include/ctype.h
thruput.o: /usr/include/signal.h
thruput.o: /usr/include/sys/signal.h
thruput.o: /usr/include/sys/stat.h
thruput.o: /usr/include/stdarg.h
thruput.o: /usr/include/varargs.h
trace.o: tcptrace.h
trace.o: /usr/include/stdio.h
trace.o: /usr/include/sys/feature_tests.h
trace.o: /usr/include/string.h
trace.o: /usr/include/sys/types.h
trace.o: /usr/include/sys/machtypes.h
trace.o: /usr/include/sys/isa_defs.h
trace.o: /usr/include/unistd.h
trace.o: /usr/include/sys/unistd.h
trace.o: /usr/include/sys/time.h
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
trace.o: /usr/include/sys/rwlock.h
trace.o: /usr/include/sys/semaphore.h
trace.o: /usr/include/sys/condvar.h
trace.o: /usr/include/sys/cred.h
trace.o: /usr/include/sys/uio.h
trace.o: /usr/include/vm/seg_enum.h
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
trace.o: /usr/include/ctype.h
trace.o: /usr/include/signal.h
trace.o: /usr/include/sys/signal.h
trace.o: /usr/include/sys/stat.h
trace.o: /usr/include/stdarg.h
trace.o: /usr/include/varargs.h
trace.o: gcache.h
