bin_PROGRAMS=dircond
dircond_SOURCES=\
 dircond.c\
 dircond.h\
 config.c\
 environ.c\
 event.c\
 hashtab.c\
 watcher.c\
 progman.c

if DIRCOND_INOTIFY
  dircond_SOURCES += ev_inotify.c
endif

if DIRCOND_KQUEUE
  dircond_SOURCES += ev_kqueue.c
endif

LDADD=@GRECS_LDADD@
AM_CPPFLAGS=-I$(top_srcdir)/grecs/src/
