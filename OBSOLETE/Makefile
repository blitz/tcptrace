#
# 	Makefile for developer's kit
#

CFLAGS = -O
CFLAGS = -O2
CFLAGS = -O2 -Wall -pg
CFLAGS = -O2 -g -pg
CFLAGS = -g
CFLAGS = -g -Wall -pg
CFLAGS = -g -Wall
CFLAGS = -O2 -Wall
#
CPPFLAGS = 
LDLIBS  = -lnsl -lsocket -lucb -lelf


OFILES=main.o trace.o plotter.o print.o netm.o snoop.o names.o gcache.o

tcptrace: ${OFILES}
	cc ${CFLAGS} ${OFILES} -o tcptrace ${LDLIBS}

tcptrace2: ${OFILES}
	cc ${CFLAGS} ${OFILES} gopen.o -o tcptrace ${LDLIBS}

clean:
	rm -f *.o tcptrace core [a-z]2[a-z] [a-z][a-z]2[a-z][a-z] *.PS.?

tidy:
	rm -f core [a-z]2[a-z] [a-z][a-z]2[a-z][a-z] *.PS.?

depend:
	mkdep *.c


# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.

gcache.o : gcache.c /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/types.h \
  /usr/include/sys/machtypes.h /usr/include/sys/select.h /usr/include/sys/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/time.h \
  tcptrace.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/stdio.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/string.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/unistd.h \
  /usr/include/sys/unistd.h /usr/include/sys/socket.h /usr/include/sys/netconfig.h \
  /usr/include/net/if.h /usr/include/netinet/in.h /usr/include/sys/stream.h /usr/include/sys/vnode.h \
  /usr/include/sys/t_lock.h /usr/include/sys/machlock.h /usr/include/sys/dki_lkinfo.h \
  /usr/include/sys/dl.h /usr/include/sys/sleepq.h /usr/include/sys/turnstile.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/param.h \
  /usr/include/sys/pirec.h /usr/include/sys/mutex.h /usr/include/sys/cred.h /usr/include/sys/uio.h \
  /usr/include/sys/poll.h /usr/include/sys/strmdep.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/byteorder.h \
  /usr/include/netinet/in_systm.h /usr/include/arpa/inet.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/if_ether.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/net/if_arp.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/ip.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/tcp.h \
  /usr/include/netdb.h gcache.h 
main.o : main.c tcptrace.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/stdio.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/string.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/types.h \
  /usr/include/sys/machtypes.h /usr/include/sys/select.h /usr/include/sys/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/unistd.h \
  /usr/include/sys/unistd.h /usr/include/sys/socket.h /usr/include/sys/netconfig.h \
  /usr/include/net/if.h /usr/include/netinet/in.h /usr/include/sys/stream.h /usr/include/sys/vnode.h \
  /usr/include/sys/t_lock.h /usr/include/sys/machlock.h /usr/include/sys/dki_lkinfo.h \
  /usr/include/sys/dl.h /usr/include/sys/sleepq.h /usr/include/sys/turnstile.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/param.h \
  /usr/include/sys/pirec.h /usr/include/sys/mutex.h /usr/include/sys/cred.h /usr/include/sys/uio.h \
  /usr/include/sys/poll.h /usr/include/sys/strmdep.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/byteorder.h \
  /usr/include/netinet/in_systm.h /usr/include/arpa/inet.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/if_ether.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/net/if_arp.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/ip.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/tcp.h \
  /usr/include/netdb.h 
names.o : names.c tcptrace.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/stdio.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/string.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/types.h \
  /usr/include/sys/machtypes.h /usr/include/sys/select.h /usr/include/sys/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/unistd.h \
  /usr/include/sys/unistd.h /usr/include/sys/socket.h /usr/include/sys/netconfig.h \
  /usr/include/net/if.h /usr/include/netinet/in.h /usr/include/sys/stream.h /usr/include/sys/vnode.h \
  /usr/include/sys/t_lock.h /usr/include/sys/machlock.h /usr/include/sys/dki_lkinfo.h \
  /usr/include/sys/dl.h /usr/include/sys/sleepq.h /usr/include/sys/turnstile.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/param.h \
  /usr/include/sys/pirec.h /usr/include/sys/mutex.h /usr/include/sys/cred.h /usr/include/sys/uio.h \
  /usr/include/sys/poll.h /usr/include/sys/strmdep.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/byteorder.h \
  /usr/include/netinet/in_systm.h /usr/include/arpa/inet.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/if_ether.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/net/if_arp.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/ip.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/tcp.h \
  /usr/include/netdb.h gcache.h 
netm.o : netm.c tcptrace.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/stdio.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/string.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/types.h \
  /usr/include/sys/machtypes.h /usr/include/sys/select.h /usr/include/sys/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/unistd.h \
  /usr/include/sys/unistd.h /usr/include/sys/socket.h /usr/include/sys/netconfig.h \
  /usr/include/net/if.h /usr/include/netinet/in.h /usr/include/sys/stream.h /usr/include/sys/vnode.h \
  /usr/include/sys/t_lock.h /usr/include/sys/machlock.h /usr/include/sys/dki_lkinfo.h \
  /usr/include/sys/dl.h /usr/include/sys/sleepq.h /usr/include/sys/turnstile.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/param.h \
  /usr/include/sys/pirec.h /usr/include/sys/mutex.h /usr/include/sys/cred.h /usr/include/sys/uio.h \
  /usr/include/sys/poll.h /usr/include/sys/strmdep.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/byteorder.h \
  /usr/include/netinet/in_systm.h /usr/include/arpa/inet.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/if_ether.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/net/if_arp.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/ip.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/tcp.h \
  /usr/include/netdb.h netm.h 
plotter.o : plotter.c tcptrace.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/stdio.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/string.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/types.h \
  /usr/include/sys/machtypes.h /usr/include/sys/select.h /usr/include/sys/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/unistd.h \
  /usr/include/sys/unistd.h /usr/include/sys/socket.h /usr/include/sys/netconfig.h \
  /usr/include/net/if.h /usr/include/netinet/in.h /usr/include/sys/stream.h /usr/include/sys/vnode.h \
  /usr/include/sys/t_lock.h /usr/include/sys/machlock.h /usr/include/sys/dki_lkinfo.h \
  /usr/include/sys/dl.h /usr/include/sys/sleepq.h /usr/include/sys/turnstile.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/param.h \
  /usr/include/sys/pirec.h /usr/include/sys/mutex.h /usr/include/sys/cred.h /usr/include/sys/uio.h \
  /usr/include/sys/poll.h /usr/include/sys/strmdep.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/byteorder.h \
  /usr/include/netinet/in_systm.h /usr/include/arpa/inet.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/if_ether.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/net/if_arp.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/ip.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/tcp.h \
  /usr/include/netdb.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/varargs.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/va-sparc.h 
print.o : print.c tcptrace.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/stdio.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/string.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/types.h \
  /usr/include/sys/machtypes.h /usr/include/sys/select.h /usr/include/sys/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/unistd.h \
  /usr/include/sys/unistd.h /usr/include/sys/socket.h /usr/include/sys/netconfig.h \
  /usr/include/net/if.h /usr/include/netinet/in.h /usr/include/sys/stream.h /usr/include/sys/vnode.h \
  /usr/include/sys/t_lock.h /usr/include/sys/machlock.h /usr/include/sys/dki_lkinfo.h \
  /usr/include/sys/dl.h /usr/include/sys/sleepq.h /usr/include/sys/turnstile.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/param.h \
  /usr/include/sys/pirec.h /usr/include/sys/mutex.h /usr/include/sys/cred.h /usr/include/sys/uio.h \
  /usr/include/sys/poll.h /usr/include/sys/strmdep.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/byteorder.h \
  /usr/include/netinet/in_systm.h /usr/include/arpa/inet.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/if_ether.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/net/if_arp.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/ip.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/tcp.h \
  /usr/include/netdb.h 
snoop.o : snoop.c tcptrace.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/stdio.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/string.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/types.h \
  /usr/include/sys/machtypes.h /usr/include/sys/select.h /usr/include/sys/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/unistd.h \
  /usr/include/sys/unistd.h /usr/include/sys/socket.h /usr/include/sys/netconfig.h \
  /usr/include/net/if.h /usr/include/netinet/in.h /usr/include/sys/stream.h /usr/include/sys/vnode.h \
  /usr/include/sys/t_lock.h /usr/include/sys/machlock.h /usr/include/sys/dki_lkinfo.h \
  /usr/include/sys/dl.h /usr/include/sys/sleepq.h /usr/include/sys/turnstile.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/param.h \
  /usr/include/sys/pirec.h /usr/include/sys/mutex.h /usr/include/sys/cred.h /usr/include/sys/uio.h \
  /usr/include/sys/poll.h /usr/include/sys/strmdep.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/byteorder.h \
  /usr/include/netinet/in_systm.h /usr/include/arpa/inet.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/if_ether.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/net/if_arp.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/ip.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/tcp.h \
  /usr/include/netdb.h snoop.h 
trace.o : trace.c tcptrace.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/stdio.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/string.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/types.h \
  /usr/include/sys/machtypes.h /usr/include/sys/select.h /usr/include/sys/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/time.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/unistd.h \
  /usr/include/sys/unistd.h /usr/include/sys/socket.h /usr/include/sys/netconfig.h \
  /usr/include/net/if.h /usr/include/netinet/in.h /usr/include/sys/stream.h /usr/include/sys/vnode.h \
  /usr/include/sys/t_lock.h /usr/include/sys/machlock.h /usr/include/sys/dki_lkinfo.h \
  /usr/include/sys/dl.h /usr/include/sys/sleepq.h /usr/include/sys/turnstile.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/param.h \
  /usr/include/sys/pirec.h /usr/include/sys/mutex.h /usr/include/sys/cred.h /usr/include/sys/uio.h \
  /usr/include/sys/poll.h /usr/include/sys/strmdep.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/sys/byteorder.h \
  /usr/include/netinet/in_systm.h /usr/include/arpa/inet.h /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/if_ether.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/net/if_arp.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/ip.h \
  /opt/cygnus-sol2-1.0/lib/gcc-lib/sparc-sun-solaris2/cygnus-2.0.2/include/netinet/tcp.h \
  /usr/include/netdb.h gcache.h 

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
