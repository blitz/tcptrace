$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!
$! Make tcptrace on OpenVMS Operating System.
$!
$! This file was modified from a "Makefile" file which was produced
$! after issuing: "./configure" on a Tru64 UNIX system.
$!
$! Supported Paramters:
$!
$!    CLEAN - deletes all output files
$!    DEBUG - turn on debug flags in compile and link
$!
$! Logicals:
$!
$!    TCPTRACE$VERIFY - if defined, then turn on verify
$!
$!  Use default directory if following logicals are not defined:
$!
$!    MAP$	      - location to write map file
$!    LIS$	      - location to write lis files
$!    OBJ$	      - location to write obj files
$!    EXE$	      - location to write exe file
$!    SRC$	      - location of source files
$!    SHRLIB$	      - location of libraries (eg. PCAP.OLB)
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!
$ on control_y then goto ctrly_handler
$ on error     then goto error_handler
$ if (f$trnlnm("tcptrace$verify") .nes. "") then SAVE_VERIFY = f$verify(1)
$!
$! Setup operating environment
$!
$ set :=
$ set symbol/scope=(nolocal, noglobal)
$!
$ NETDEF = 0
$ DEFDIR  = f$environment("DEFAULT")
$ PCAPLIB = DEFDIR - "]" + ".-.PCAP.OBJ]"  !!!! Directory of PCAP.OLB !!!!
$!
$ call define_concealed base_root 'DEFDIR'
$ call define_concealed tcptrace_root 'DEFDIR'
$!
$ if f$trnlnm("src$") .eqs. "" then define src$ base_root:[000000]
$ if f$trnlnm("lis$") .eqs. "" then define lis$ base_root:[lis]
$ if f$trnlnm("obj$") .eqs. "" then define obj$ base_root:[obj]
$ if f$trnlnm("exe$") .eqs. "" then define exe$ base_root:[exe]
$ if f$trnlnm("map$") .eqs. "" then define map$ exe$  ! map file in exe dir
$!
$! Sanity test - make sure SRC$ points to these sources
$!
$ if f$search("src$:tcptrace.c") .eqs. ""
$ then
$   write sys$output ""
$   write sys$output "Cannot find SRC$:TCPTRACE.C - Verify the logicals are correct"
$   write sys$output ""
$   write sys$output "   SRC$      = ''f$trnlnm(""src$"")'"
$   write sys$output "   BASE_ROOT = ''f$trnlnm(""base_root"")'"
$   write sys$output ""
$   goto exit
$ endif
$!
$! Create output directories if needed.
$!
$ if f$parse("lis$") .eqs. "" then create/dir/log lis$
$ if f$parse("obj$") .eqs. "" then create/dir/log obj$
$ if f$parse("exe$") .eqs. "" then create/dir/log exe$
$!
$ if f$trnlnm("shrlib$") .eqs. "" then define shrlib$ 'PCAPLIB'
$!
$ P1 = f$edit(P1, "COLLAPSE,UPCASE")
$ if "''P1'" .eqs. "CLEAN
$ then
$   write sys$output "Cleaning all output files..."
$   set noon
$   define/user sys$output nl:
$   define/user sys$error nl:
$   delete/nolog obj$:*.obj.*, lis$:*.lis.*, exe$:*.exe.*, -
		 map$:*.map.*, exe$:*.dsf.*, obj$:*.opt.*
$   set on
$   goto exit
$ endif
$!
$! Compiler gets confused with device NET0:, a DECnet device.
$! This needs workaround when including files from net, eg. <net/bpf.h>
$!
$ if f$trnlnm("net") .eqs. ""
$ then
$    define net src$  ! could be defined as junk
$    NETDEF = 1
$ else
$    write sys$output "NET is currently defined and will not be redefined"
$    write sys$output "    NET = ''f$trnlnm(""net"")'"
$ endif
$!
$ ARCH = f$getsyi("ARCH_NAME")
$ USER_NAME = f$user()
$ SCSNODE = f$getsyi("NODENAME")
$ TIME = f$time()
$!
$! Use of double-quote gets tricky for subsequent symbol substitution!
$!
$ DEFINES = ",BUILT_USER=""""""''USER_NAME'""""""" + -
	  ",BUILT_HOST=""""""''SCSNODE'""""""" + -
	  ",BUILT_DATE=""""""''TIME'"""""""
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!
$! tcptrace supports reading compressed files with a little help...
$! 1) If your system has "gunzip", then uncomment the following line to
$!    support on-the-fly decompression of ".gz" and ".Z" files...
$ DEFINES = DEFINES + ",GUNZIP=""""""gunzip"""""""
$!
$!
$! 2) Otherwise, if your system supports standard Unix "uncompress",
$!    then uncomment the following line to support on-the-fly
$!    decompression of ".Z" files...
$!DEFINES = DEFINES + ",UNCOMPRESS=""""""uncompress"""""""
$!
$!
$! 3) Also, we assume most systems have the "bunzip2" utility installed,
$!    if yours doesn't, you'll want to comment out the next line.
$!DEFINES = DEFINES + ",BUNZIP2=""""""bunzip2"""""""
$!
$!
$! - we'll do path search on the string you specify.  If the program
$!    isn't in your path, you'll need to give the absolute path name.
$! - if you want other formats, see the "compress.h" file.
$!
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!
$! If you want to read tcpdump output (which you probably do),
$! you'll need the LBL PCAP library.  If it's somewhere else,
$! just modify the symbol.
$! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$ PCAP_LDLIBS  = "shrlib$:pcap/libr"
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$! 
$! Plug-in modules.
$! There's no reason that I can think of to remove them, but
$! here they are.  Just comment them out to omit them from
$! the binary.
$! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$! 
$! Experimental HTTP analysis module
$! 
$ DEFINES = DEFINES + ",LOAD_MODULE_HTTP, HTTP_SAFE, HTTP_DUMP_TIMES"
$! 
$! Experimental overall traffic by port module
$! 
$ DEFINES = DEFINES + ",LOAD_MODULE_TRAFFIC"
$! 
$! Experimental traffic data by time slices module
$! 
$ DEFINES = DEFINES + ",LOAD_MODULE_SLICE"
$! 
$! Experimental round trip time graphs
$! 
$ DEFINES = DEFINES + ",LOAD_MODULE_RTTGRAPH"
$! 
$! Experimental tcplib-data generating module
$! 
$!DEFINES += -DLOAD_MODULE_TCPLIB
$! 
$! Experimental module for a friend
$! 
$ DEFINES = DEFINES + ",LOAD_MODULE_COLLIE"
$! 
$! Example module for real-time mode 
$! 
$ DEFINES = DEFINES + ",LOAD_MODULE_REALTIME"
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$! 
$! File formats that we understand.
$! The only reason that I can see to remove one is if you don't
$! have the PCAP library, in which case you can comment out
$! GROK_TCPDUMP and still compile, but then you can't read the
$! output from tcpdump.
$! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$! define GROK_SNOOP if you want tcptrace to understand the output
$! format of Sun's "snoop" packet sniffer.
$ DEFINES = DEFINES + ",GROK_SNOOP"
$!
$! define GROK_TCPDUMP if you want tcptrace to understand the output
$! format format of the LBL tcpdump program (see the file README.tcpdump
$! for other options)
$ DEFINES = DEFINES +",GROK_TCPDUMP"
$!
$! define GROK_NETM if you want tcptrace to understand the output
$! format of HP's "netm" monitoring system's packet sniffer.
$ DEFINES = DEFINES + ",GROK_NETM"
$!
$! define GROK_ETHERPEEK if you want tcptrace to understand the output
$! format of the Macintosh program Etherpeek
$!DEFINES = DEFINES + ",GROK_ETHERPEEK"
$!
$! define GROK_NS if you want tcptrace to understand the output
$! format of the LBL network simulator, ns
$ DEFINES = DEFINES + ",GROK_NS"
$!
$! define GROK_NLANR if you want tcptrace to understand the output
$! format of the various NLANL tools
$! (this doesn't work well yet, not recommended - Sat Dec 19, 1998)
$! DEFINES = DEFINES + ",GROK_NLANR"
$!
$! define GROK_NETSCOUT if you want tcptrace to understand ascii
$! formatted netscout output files
$ DEFINES = DEFINES + ",GROK_NETSCOUT"
$!
$! If you get multiple defines for "inet_pton", then uncomment next define
$!
$!   DEFINES = DEFINES + ",HAVE_INET_PTON=1"
$!
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$! 
$! Name of executable and name of foreign command used to run it.
$! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!
$! Name of executable
$ EXEFILE = "tcptrace"
$ FOREIGN = "tcpanal"
$!
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$! 
$! You shouldn't need to change anything below this point
$! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
$!
$ CC = "CC"
$ CCOPT = ""
$ INCLS = ""
$!
$ DEFINES = DEFINES + -
       ", SIZEOF_UNSIGNED_LONG_LONG_INT=8" + -
       ", SIZEOF_UNSIGNED_LONG_INT=4, SIZEOF_UNSIGNED_INT=4" + -
       ", SIZEOF_UNSIGNED_SHORT=2, HAVE_MKSTEMP=1" + -
       ", USE_LLU=1"
$ DEFINES = DEFINES - "," ! remove leading , character
$ CFLAGS = CCOPT
$!
$! Standard LIBS
$ LDLIBS = PCAP_LDLIBS
$! 
$! Source Files
$! 
$ CFILES="compress, etherpeek, gcache, mfiles, names" + -
	", netm, output, plotter, print, rexmit, snoop, nlanr" + -
	", tcpdump, tcptrace, thruput, trace, ipv6" + -
	", filt_scanner, filt_parser, filter, udp" + -
	", ns, netscout, pool, poolaccess" + -
	", dstring"
$ MODULES=", mod_http, mod_traffic, mod_rttgraph, mod_tcplib, mod_collie" + -
	", mod_slice, mod_realtime"
MODSUPPORT=", dyncounter"
VMS_FILES=", snprintf_vms"
$!
$! Retreive filt_parser and filt_scanner from flex_bison subdirectory.
$!
$ if f$search("src$:filt_parser.c") .eqs. ""
$ then
$   FLEX_BISON = DEFDIR - "]" + ".flex_bison]"
$   write sys$output "Retreiving filt_parser and filt_scanner from ''FLEX_BISON'..."
$   backup 'FLEX_BISON'filt_parser.c src$
$   backup 'FLEX_BISON'filt_parser.h src$
$   backup 'FLEX_BISON'filt_scanner.c src$
$ endif  
$!
$ OFILES = CFILES + MODULES + MODSUPPORT + VMS_FILES
$ OFILES = f$edit(OFILES,"TRIM,COMPRESS")
$!
$ CC_FILE = ""
$ INDEX = 0
$ CC_OPTS = ""
$ LINK_OPTS = ""
$ if "''P1'" .eqs. "DEBUG"
$ then
$   write sys$output "Building debug image..."
$   CC_OPTS =  "/DEBUG/NOOPTIMIZE/LIS=lis$/SHOW=ALL"
$   LINK_OPTS =  "/DEBUG /DSF=exe$:''EXEFILE'/MAP=map$ /FULL /CROSS"
$ endif   
$!
$ cc_loop:
$   FILE_NAME = f$edit(f$element(INDEX, ",", OFILES), "COLLAPSE")
$   if FILE_NAME .eqs. "," then goto cc_done
$   INDEX = INDEX + 1
$   !
$   ! Is file up to date?  Compare revision date and time of
$   ! OBJ file with C file.  (Poor man's dependency checking).
$   !
$   OUT_OF_DATE = "TRUE"
$   OBJFILE = "obj$:" + FILE_NAME + ".obj"
$   if f$search(OBJFILE) .nes. ""
$   then
$      RDT_C = f$cvtime(f$file_attributes("src$:" + FILE_NAME + ".c", "RDT"))
$      RDT_OBJ = f$cvtime(f$file_attributes(OBJFILE, "RDT"))
$      if RDT_C .lts. RDT_OBJ then OUT_OF_DATE = "FALSE"
$   endif
$   if OUT_OF_DATE .eqs. "TRUE"
$   then
$      CC_FILE = FILE_NAME
$      write sys$output "Compiling src$:''CC_FILE'..."
$      CC src$:'CC_FILE'+src$:includes_vms/libr -
       'CC_OPTS' -
       /OBJ=obj$ -
       /WARN=(NOINFORMATIONALS) -
       /NAMES=AS_IS -
       /DEFINE=('DEFINES')
$      CC_FILE = ""  ! only executed if compile is successful
$   else
$      write sys$output "src$:''FILE_NAME' up to date."
$   endif
$   goto cc_loop
$ cc_done:
$!
$ link_phase:
$!
$! Sanity check for link dependencies
$!
$   if f$search("shrlib$:pcap.olb") .eqs. ""
$   then
$      write sys$output ""
$      write sys$output "Warning - SHRLIB$:PCAP.OLB not found"
$      write sys$output "Verify logical SHRLIB$ is correct.  Deassign it if needed."
$      write sys$output ""
$      write sys$output "  SHRLIB$ = ''f$trnlnm(""shrlib$"")'"
$      write sys$output ""
$      goto exit
$   endif
$   OPTFILE = "src$:" + EXEFILE + ".opt"
$   INDEX = 0
$!
$   CC_FILE = "version"  ! compile this each build
$   write sys$output "Compiling src$:''CC_FILE'..."
$   CC src$:'CC_FILE' -
       'CC_OPTS' -
       /OBJ=obj$ -
       /WARN=(NOINFORMATIONALS) -
       /NAMES=AS_IS -
       /DEFINE=('DEFINES')
$   CC_FILE = ""  ! only executed if compile is successful
$   write sys$output "Linking exe$:''EXEFILE'..."
$   link 'LINK_OPTS' 'OPTFILE'/OPT /EXE=exe$:'EXEFILE' +'LDLIBS'
$!
$!  All done.  Create a foreign command to run this EXEFILE.
$!
$   write sys$output "Success!"
$   write sys$output "Foreign command defined as:"
$   set symbol/scope=(nolocal,global) ! need to define global symbol
$   'FOREIGN' :== $tcptrace_root:[exe]'EXEFILE'.exe
$   show symbol 'FOREIGN'
$   set symbol/scope=(nolocal,noglobal)
$   write sys$output "Use foreign command ""''FOREIGN'"" to run ""''EXEFILE'"""
$   goto exit
$!
$ file_error:
$   write sys$output "Error writing file ''OPTFILE'"
$   goto error_handler
$!
$ ctrly_handler:
$   write sys$output "<CTRL-C> pressed.  Exiting.
$!
$ error_handler:
$   ! Assume module being compiled did not complete, so cleanup
$   OBJFILE = "obj$:''CC_FILE'.obj"
$   if f$search(OBJFILE) .nes. ""
$   then
$      write sys$output "Cleaning up ''OBJFILE'"
$      delete/nolog 'OBJFILE';*
$   endif
$!
$ exit:
$   set noon
$   if NETDEF .eq. 1 then deassign net
$   if (f$type(SAVE_VERIFY) .eqs. "") then exit 1
$   exit 1 + (0 * 'f$verify(SAVE_VERIFY)')
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$ define_concealed:
$ subroutine
$!
$! P1 - name of concealed logical to be defined
$! P2 - directory specification to become the root
$! P3 - optional switches to the "define" command
$!
$! Contributed by John Gillings, Sydney CSC.
$!
$ CONC = f$trnlnm(f$parse(P2,,,"DEVICE") - ":")
$ if f$locate("<",CONC) .lt. f$length(CONC)
$ then
$   L="<"
$   R=">"
$ else
$   L="["
$   R="]"
$ endif
$ TRANS = (f$parse(P2,,,"DEVICE","NO_CONCEAL")+-
           f$parse(P2,L+"000000"+R,,"DIRECTORY","NO_CONCEAL")) - -
          (R+L)-("000000"+R)-("."+R)+"*"-".*"-"*"-R+("."+R)-(L+"."+R)
$ define/translation_attributes=(terminal,concealed)'P3' 'P1' 'TRANS'
$ exit 1 ! success
$ endsubroutine
