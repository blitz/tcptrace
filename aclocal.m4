dnl @(#) $Header$ (LBL)
dnl
dnl Copyright (c) 1995, 1996, 1997
dnl	The Regents of the University of California.  All rights reserved.
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that: (1) source code distributions
dnl retain the above copyright notice and this paragraph in its entirety, (2)
dnl distributions including binary code include the above copyright notice and
dnl this paragraph in its entirety in the documentation or other materials
dnl provided with the distribution, and (3) all advertising materials mentioning
dnl features or use of this software display the following acknowledgement:
dnl ``This product includes software developed by the University of California,
dnl Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
dnl the University nor the names of its contributors may be used to endorse
dnl or promote products derived from this software without specific prior
dnl written permission.
dnl THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
dnl WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
dnl MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
dnl
dnl LBL autoconf macros
dnl

dnl
dnl Determine which compiler we're using (cc or gcc)
dnl If using gcc, determine the version number
dnl If using cc, require that it support ansi prototypes
dnl If using gcc, use -O2 (otherwise use -O)
dnl If using cc, explicitly specify /usr/local/include
dnl
dnl usage:
dnl
dnl	AC_LBL_C_INIT(copt, incls)
dnl
dnl results:
dnl
dnl	$1 (copt set)
dnl	$2 (incls set)
dnl	CC
dnl	ac_cv_lbl_gcc_vers
dnl	LBL_CFLAGS
dnl
AC_DEFUN(AC_LBL_C_INIT,
    [AC_PREREQ(2.12)
    AC_BEFORE([$0], [AC_PROG_CC])
    AC_BEFORE([$0], [AC_LBL_FIXINCLUDES])
    AC_BEFORE([$0], [AC_LBL_DEVEL])
    AC_ARG_WITH(gcc, [  --without-gcc           don't use gcc])
    $1="-O"
    $2=""
    if test "${CFLAGS+set}" = set; then
	    LBL_CFLAGS="$CFLAGS"
    fi
    if test -z "$CC" ; then
	    case "$target_os" in

	    bsdi*)
		    AC_CHECK_PROG(SHLICC2, shlicc2, yes, no)
		    if test $SHLICC2 = yes ; then
			    CC=shlicc2
			    export CC
		    fi
		    ;;
	    esac
    fi
    if test -z "$CC" -a "$with_gcc" = no ; then
	    CC=cc
	    export CC
    fi
    AC_PROG_CC
    if test "$GCC" = yes ; then
	    if test "$SHLICC2" = yes ; then
		    ac_cv_lbl_gcc_vers=2
		    $1="-O2"
	    else
		    AC_MSG_CHECKING(gcc version)
		    AC_CACHE_VAL(ac_cv_lbl_gcc_vers,
			ac_cv_lbl_gcc_vers=`$CC -v 2>&1 | \
			    sed -n -e '$s/.* //' -e '$s/\..*//p'`)
		    AC_MSG_RESULT($ac_cv_lbl_gcc_vers)
		    if test $ac_cv_lbl_gcc_vers -gt 1 ; then
			    $1="-O2"
		    fi
	    fi
    else
	    AC_MSG_CHECKING(that $CC handles ansi prototypes)
	    AC_CACHE_VAL(ac_cv_lbl_cc_ansi_prototypes,
		AC_TRY_COMPILE(
		    [#include <sys/types.h>],
		    [int frob(int, char *)],
		    ac_cv_lbl_cc_ansi_prototypes=yes,
		    ac_cv_lbl_cc_ansi_prototypes=no))
	    AC_MSG_RESULT($ac_cv_lbl_cc_ansi_prototypes)
	    if test $ac_cv_lbl_cc_ansi_prototypes = no ; then
		    case "$target_os" in

		    hpux*)
			    AC_MSG_CHECKING(for HP-UX ansi compiler ($CC -Aa -D_HPUX_SOURCE))
			    savedcflags="$CFLAGS"
			    CFLAGS="-Aa -D_HPUX_SOURCE $CFLAGS"
			    AC_CACHE_VAL(ac_cv_lbl_cc_hpux_cc_aa,
				AC_TRY_COMPILE(
				    [#include <sys/types.h>],
				    [int frob(int, char *)],
				    ac_cv_lbl_cc_hpux_cc_aa=yes,
				    ac_cv_lbl_cc_hpux_cc_aa=no))
			    AC_MSG_RESULT($ac_cv_lbl_cc_hpux_cc_aa)
			    if test $ac_cv_lbl_cc_hpux_cc_aa = no ; then
				    AC_MSG_ERROR(see the INSTALL doc for more info)
			    fi
			    CFLAGS="$savedcflags"
			    V_CCOPT="-Aa $V_CCOPT"
			    AC_DEFINE(_HPUX_SOURCE)
			    ;;

		    *)
			    AC_MSG_ERROR(see the INSTALL doc for more info)
			    ;;
		    esac
	    fi
	    $2="-I/usr/local/include"

	    case "$target_os" in

	    irix*)
		    V_CCOPT="$V_CCOPT -xansi -signed -g3"
		    ;;

	    osf*)
		    V_CCOPT="$V_CCOPT -g3"
		    ;;

	    ultrix*)
		    AC_MSG_CHECKING(that Ultrix $CC hacks const in prototypes)
		    AC_CACHE_VAL(ac_cv_lbl_cc_const_proto,
			AC_TRY_COMPILE(
			    [#include <sys/types.h>],
			    [struct a { int b; };
			    void c(const struct a *)],
			    ac_cv_lbl_cc_const_proto=yes,
			    ac_cv_lbl_cc_const_proto=no))
		    AC_MSG_RESULT($ac_cv_lbl_cc_const_proto)
		    if test $ac_cv_lbl_cc_const_proto = no ; then
			    AC_DEFINE(const,)
		    fi
		    ;;
	    esac
    fi
])

dnl
dnl Checks to see if unaligned memory accesses fail
dnl
dnl usage:
dnl
dnl	AC_LBL_UNALIGNED_ACCESS
dnl
dnl results:
dnl
dnl	LBL_ALIGN (DEFINED)
dnl
AC_DEFUN(AC_LBL_UNALIGNED_ACCESS,
    [AC_MSG_CHECKING(if unaligned accesses fail)
    AC_CACHE_VAL(ac_cv_lbl_unaligned_fail,
	[case "$target_cpu" in

	alpha|hp*|mips|sparc)
		ac_cv_lbl_unaligned_fail=yes
		;;

	*)
		cat >conftest.c <<EOF
#		include <sys/types.h>
#		include <sys/wait.h>
#		include <stdio.h>
		unsigned char a[[5]] = { 1, 2, 3, 4, 5 };
		main() {
		unsigned int i;
		pid_t pid;
		int status;
		/* avoid "core dumped" message */
		pid = fork();
		if (pid <  0)
			exit(2);
		if (pid > 0) {
			/* parent */
			pid = waitpid(pid, &status, 0);
			if (pid < 0)
				exit(3);
			exit(!WIFEXITED(status));
		}
		/* child */
		i = *(unsigned int *)&a[[1]];
		printf("%d\n", i);
		exit(0);
		}
EOF
		${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS \
		    conftest.c $LIBS >/dev/null 2>&1
		if test ! -x conftest ; then
			dnl failed to compile for some reason
			ac_cv_lbl_unaligned_fail=yes
		else
			./conftest >conftest.out
			if test ! -s conftest.out ; then
				ac_cv_lbl_unaligned_fail=yes
			else
				ac_cv_lbl_unaligned_fail=no
			fi
		fi
		rm -f conftest* core core.conftest
		;;
	esac])
    AC_MSG_RESULT($ac_cv_lbl_unaligned_fail)
    if test $ac_cv_lbl_unaligned_fail = yes ; then
	    AC_DEFINE(LBL_ALIGN)
    fi])


dnl
dnl If using gcc and the file .devel exists:
dnl	Compile with -g (if supported) and -Wall
dnl	If using gcc 2, do extra prototype checking
dnl	If an os prototype include exists, symlink os-proto.h to it
dnl
dnl usage:
dnl
dnl	AC_LBL_DEVEL(copt)
dnl
dnl results:
dnl
dnl	$1 (copt appended)
dnl	HAVE_OS_PROTO_H (defined)
dnl	os-proto.h (symlinked)
dnl
AC_DEFUN(AC_LBL_DEVEL,
    [rm -f os-proto.h
    if test "${LBL_CFLAGS+set}" = set; then
	    $1="$$1 ${LBL_CFLAGS}"
    fi
    if test -f .devel ; then
	    if test "$GCC" = yes ; then
		    if test "${LBL_CFLAGS+set}" != set; then
			    if test "$ac_cv_prog_cc_g" = yes ; then
				    $1="-g $$1"
			    fi
			    $1="$$1 -Wall"
			    if test $ac_cv_lbl_gcc_vers -gt 1 ; then
				    $1="$$1 -pedantic -Wmissing-prototypes -Wstrict-prototypes"
			    fi
		    fi
	    else
		    case "$target_os" in

		    irix6*)
			    V_CCOPT="$V_CCOPT -n32"
			    ;;

		    *)
			    ;;
		    esac
	    fi
	    os=`echo $target_os | sed -e 's/\([[0-9]][[0-9]]*\)[[^0-9]].*$/\1/'`
	    name="lbl/os-$os.h"
	    if test -f $name ; then
		    ln -s $name os-proto.h
		    AC_DEFINE(HAVE_OS_PROTO_H)
	    else
		    AC_MSG_WARN(can't find $name)
	    fi
    fi])

dnl
dnl Attempt to determine additional libraries needed for network programs
dnl
dnl Thanks to John Hawkinson (jhawk@mit.edu)
dnl
dnl usage:
dnl
dnl	AC_LBL_LIBRARY_NET
dnl
dnl results:
dnl
dnl	LIBS
dnl

define(AC_LBL_CHECK_LIB,
[AC_MSG_CHECKING([for $2 in -l$1])
dnl Use a cache variable name containing both the library and function name,
dnl because the test really is for library $1 defining function $2, not
dnl just for library $1.  Separate tests with the same $1 and different $2s
dnl may have different results.
ac_lib_var=`echo $1['_']$2['_']$5 | sed 'y%./+- %__p__%'`
AC_CACHE_VAL(ac_cv_lbl_lib_$ac_lib_var,
[ac_save_LIBS="$LIBS"
LIBS="-l$1 $5 $LIBS"
AC_TRY_LINK(dnl
ifelse([$2], [main], , dnl Avoid conflicting decl of main.
[/* Override any gcc2 internal prototype to avoid an error.  */
]ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
extern "C"
#endif
])dnl
[/* We use char because int might match the return type of a gcc2
    builtin and then its argument prototype would still apply.  */
char $2();
]),
	    [$2()],
	    eval "ac_cv_lbl_lib_$ac_lib_var=yes",
	    eval "ac_cv_lbl_lib_$ac_lib_var=no")
LIBS="$ac_save_LIBS"
])dnl
if eval "test \"`echo '$ac_cv_lbl_lib_'$ac_lib_var`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$3], ,
[changequote(, )dnl
  ac_tr_lib=HAVE_LIB`echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_lib)
  LIBS="-l$1 $LIBS"
], [$3])
else
  AC_MSG_RESULT(no)
ifelse([$4], , , [$4
])dnl
fi
])

dnl
dnl AC_LBL_LIBRARY_NET
dnl
dnl This test is for network applications that need socket() and
dnl gethostbyname() -ish functions.  Under Solaris, those applications
dnl need to link with "-lsocket -lnsl".  Under IRIX, they need to link
dnl with "-lnsl" but should *not* link with "-lsocket" because
dnl libsocket.a breaks a number of things (for instance:
dnl gethostbyname() under IRIX 5.2, and snoop sockets under most
dnl versions of IRIX).
dnl
dnl Unfortunately, many application developers are not aware of this,
dnl and mistakenly write tests that cause -lsocket to be used under
dnl IRIX.  It is also easy to write tests that cause -lnsl to be used
dnl under operating systems where neither are necessary (or useful),
dnl such as SunOS 4.1.4, which uses -lnsl for TLI.
dnl
dnl This test exists so that every application developer does not test
dnl this in a different, and subtly broken fashion.

dnl It has been argued that this test should be broken up into two
dnl seperate tests, one for the resolver libraries, and one for the
dnl libraries necessary for using Sockets API. Unfortunately, the two
dnl are carefully intertwined and allowing the autoconf user to use
dnl them independantly potentially results in unfortunate ordering
dnl dependancies -- as such, such component macros would have to
dnl carefully use indirection and be aware if the other components were
dnl executed. Since other autoconf macros do not go to this trouble,
dnl and almost no applications use sockets without the resolver, this
dnl complexity has not been implemented.
dnl
dnl The check for libresolv is in case you are attempting to link
dnl statically and happen to have a libresolv.a lying around (and no
dnl libnsl.a).
dnl
AC_DEFUN(AC_LBL_LIBRARY_NET, [
    # Most operating systems have gethostbyname() in the default searched
    # libraries (i.e. libc):
    AC_CHECK_FUNC(gethostbyname, ,
	# Some OSes (eg. Solaris) place it in libnsl:
	AC_LBL_CHECK_LIB(nsl, gethostbyname, , 
	    # Some strange OSes (SINIX) have it in libsocket:
	    AC_LBL_CHECK_LIB(socket, gethostbyname, ,
		# Unfortunately libsocket sometimes depends on libnsl.
		# AC_CHECK_LIB's API is essentially broken so the
		# following ugliness is necessary:
		AC_LBL_CHECK_LIB(socket, gethostbyname,
		    LIBS="-lsocket -lnsl $LIBS",
		    AC_CHECK_LIB(resolv, gethostbyname),
		    -lnsl))))
    AC_CHECK_FUNC(socket, , AC_CHECK_LIB(socket, socket, ,
	AC_LBL_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", ,
	    -lnsl)))
    # DLPI needs putmsg under HPUX so test for -lstr while we're at it
    AC_CHECK_LIB(str, putmsg)
    ])
