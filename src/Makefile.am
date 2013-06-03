bin_PROGRAMS=dircond
dircond_SOURCES=\
 dircond.c\
 dircond.h\
 cmdline.h\
 config.c\
 environ.c\
 event.c\
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
	m4 -s $(top_srcdir)/@GRECS_SUBDIR@/build-aux/getopt.m4 $< > $@

