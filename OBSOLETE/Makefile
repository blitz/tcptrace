#
# Makefile for tcptrace
#

#   
# User-configurable constants
#
CC	= gcc

#
# tcptrace supports reading compressed files with a little help...
# 1) If your system supports "gunzip", then uncomment the following line to
#    support on-the-fly decompression of ".gz" and ".Z" files...
COMPRESSION += -DGUNZIP="\"gunzip\""
# 2) Otherwise, if your system supports standard Unix "uncompress",
#    then uncomment the following line to support on-the-fly
#    decompression of ".Z" files...
#COMPRESSION += -DUNCOMPRESS="\"uncompress\""
# - we'll do path search on the string you specify.  If the program
#    isn't in your path, you'll need to give the absolute path name.
# - if you want other formats, see the "compress.h' file.


#
# According to Jeff Semke, this define allows the program to compile
# and run under NetBSD on a pentium box.
#
#DEFINES = -DI386_NBSD1
#
# According to Rich Jones at HP, there is no ether_ntoa under HPUX.
# I added one in the file missing.c
# If _YOU_ need it, just define NEED_ETHER_NTOA
#
# The same seems to hold for some versions of Linux.  Just define the
# following:
#
#DEFINES = -DNEED_ETHER_NTOA
#


#
# If you're using linux, with it's weird include file changes, better
# to use the ones supplied here, which are the standard (Public
# Domain) versions (with a couple of minor edits by sdo)...
#
#INCS = -Ilinux-include

#
# If you're using the pcap library, you'll need to add its include and
# library location, otherwise the default should be fine
# 
INCS	+= -I/usr/local/include
LDFLAGS = -L/usr/local/lib

#
# For HP:  (Rick Jones)
# CFLAGS	= -Ae -Wall ${INCS} ${COMPRESSION}
#
# For FreeBSD:
# CFLAGS += -fno-builtin ${INCS} ${DEFINES} ${COMPRESSION}
#
# For Solaris:
#   Warning, without -fno-builtin, a bug in gcc 2.7.2 forces an
#   alignment error on my Sparc when it re-writes memcpy()...
#
#CFLAGS	= -g -O3 -fno-builtin -Wall ${INCS} ${DEFINES} ${COMPRESSION}
#
CFLAGS	= -g -O3 -fno-builtin -Wall ${INCS} ${DEFINES} ${COMPRESSION}


# for profiling (under Solaris 5.2)
#CFLAGS	+= -pg
#LDFLAGS += /usr/lib/libdl.so.1

# for testing "cleanness" before distribution
#CFLAGS	+= -pedantic -Wall

#
# All the different libraries, differ from machine to machine
#
# Math library required (on most machines, at least)
#
# For Solaris
# LDLIBS = -lpcap -lnsl -lsocket -lm
#
# For SunOS
# LDLIBS = -lpcap -lm
#
# For HP
# LDLIBS = -lpcap -lstr -lm
#
# for NetBSD
# LDLIBS = -lpcap -lm
#
# for FreeBSD
# LDLIBS = -lpcap -lm
#
# for Linux
# LDLIBS = -lpcap -lm
#
# for general Unix boxes (I hope)
# LDLIBS = -lpcap -lm
#
LDLIBS = -lnsl -lsocket -lm -lpcap



# Plug-in modules (if you want any)
MODULES= mod_http.c mod_traffic.c

# Standard files
CFILES= etherpeek.c gcache.c tcptrace.c mfiles.c names.c netm.c output.c \
	plotter.c print.c snoop.c tcpdump.c thruput.c trace.c rexmit.c \
	missing.c compress.c
OFILES= ${CFILES:.c=.o} ${MODULES:.c=.o}



tcptrace: ${OFILES}
	${CC} ${LDFLAGS} ${CFLAGS} ${OFILES} -o tcptrace ${LDLIBS}


#
# obvious dependencies
#
${OFILES}: tcptrace.h config.h


#
# just for RCS
ci:
	ci -u -q -t-initial -mlatest Makefile README* CHANGES *.h *.c

#
# for cleaning up
clean:
	rm -f *.o tcptrace core *.xpl *.dat
noplots:
	rm -f *.xpl *.dat

#
# for making distribution
tarfile:
	cd ..; /usr/sbin/tar -FFcfv $$HOME/tcptrace.tar tcptrace
	gzip $$HOME/tcptrace.tar
#
# similar, but include RCS directory and etc
bigtarfile:
	cd ..; /usr/sbin/tar -cfv $$HOME/tcptrace.tar tcptrace


#
# static file dependencies
#
etherpeek.o: tcptrace.h config.h
gcache.o: tcptrace.h config.h gcache.h
mfiles.o: tcptrace.h config.h
mod_http.o: tcptrace.h config.h mod_http.h
names.o: tcptrace.h config.h gcache.h
netm.o: tcptrace.h config.h
output.o: tcptrace.h config.h gcache.h
plotter.o: tcptrace.h config.h
print.o: tcptrace.h config.h
rexmit.o: tcptrace.h config.h
rtt.o: tcptrace.h config.h
snoop.o: tcptrace.h config.h
tcpdump.o: tcptrace.h tcpdump.h config.h
tcptrace.o: tcptrace.h config.h file_formats.h modules.h mod_http.h version.h
thruput.o: tcptrace.h config.h
trace.o: tcptrace.h config.h gcache.h
compress.o: tcptrace.h config.h compress.h
mod_http.o: tcptrace.h config.h
mod_traffic.o: tcptrace.h config.h mod_traffic.h

#
# generate dependencies
depend:
	makedepend ${INCS} -w 10 *.c
