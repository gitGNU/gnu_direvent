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

bin_PROGRAMS=dircond
dircond_SOURCES=\
 dircond.c\
 dircond.h\
 cmdline.h\
 config.c\
 environ.c\
 event.c\
 fnpat.c\
 hashtab.c\
 watcher.c\
 progman.c\
 sigv.c

if DIRCOND_INOTIFY
  dircond_SOURCES += ev_inotify.c detach-std.c
endif

if DIRCOND_KQUEUE
  dircond_SOURCES += ev_kqueue.c
if DIRCOND_RFORK
  dircond_SOURCES += detach-bsd.c
else
  dircond_SOURCES += detach-darwin.c
endif
endif

LDADD=@GRECS_LDADD@
AM_CPPFLAGS=-I$(top_srcdir)/grecs/src/

BUILT_SOURCES=cmdline.h
EXTRA_DIST=cmdline.opt

SUFFIXES=.opt .c .h
.opt.h:
	$(AM_V_GEN)m4 -s $(top_srcdir)/@GRECS_SUBDIR@/build-aux/getopt.m4 $< > $@

