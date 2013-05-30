# This file is part of Dircond -*- autoconf -*-
# Copyright (C) 2012, 2013 Sergey Poznyakoff
#
# Dircond is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Dircond is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Dircond.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.69])
AC_INIT([dircond], [3.99.90], [gray+dircond@gnu.org.ua],,
        [http://www.gnu.org.ua/software/dircond])
AC_CONFIG_SRCDIR([src/dircond.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11.5 gnu tar-ustar])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([sys/inotify.h sys/event.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([inotify_init kqueue])

if test "$ac_cv_header_sys_inotify_h/$ac_cv_func_inotify_init" = yes/yes; then
  iface=inotify
elif test "$ac_cv_header_sys_event_h/$ac_cv_func_kqueue" = yes/yes; then
  iface=kqueue
else
  AC_MSG_ERROR([no suitable interface found])
fi

AM_CONDITIONAL([DIRCOND_INOTIFY],[test $iface = inotify])
AM_CONDITIONAL([DIRCOND_KQUEUE],[test $iface = kqueue])
AC_SUBST(IFACE, $iface)
AC_DEFINE_UNQUOTED(USE_IFACE,IFACE_`echo $iface|tr a-z A-Z`,
                   [event notification interface to use])
AH_TOP([
/* Supported event notification types */
#define IFACE_INOTIFY 0  /* inotify - Linux */
#define IFACE_KQUEUE  1  /* kqueue  - BSD */
])

# Grecs subsystem

GRECS_SETUP([grecs],[tree-api git2chg no-preproc getopt])

AC_CONFIG_COMMANDS([status],[
cat <<EOT

Selected interface: $iface

EOT
],[
iface=$iface
])

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 doc/Makefile])
AC_OUTPUT
