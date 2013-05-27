bin_PROGRAMS=dircond
dircond_SOURCES=\
 dircond.c\
 dircond.h\
 config.c\
 event.c\
 hashtab.c\
 watcher.c\
 pathdefn.c

if DIRCOND_INOTIFY
  dircond_SOURCES += ev_inotify.c
endif

if DIRCOND_KQUEUE
  dircond_SOURCES += ev_kqueue.c
endif

dist_man_MANS=dircond.1

.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                   \
		git log --pretty='format:%ct  %an  <%ae>%n%n%s%n%n%b%n' |  \
		awk -f $(top_srcdir)/git2chg.awk > ChangeLog; \
        fi

EXTRA_DIST=git2chg.awk
