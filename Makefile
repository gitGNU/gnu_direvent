# dircond - directory content watcher daemon
# Copyright (C) 2012, 2013 Sergey Poznyakoff
#
# Dircond is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at your
# option) any later version.
#
# Dircond is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with dircond. If not, see <http://www.gnu.org/licenses/>.

CFLAGS=-O2 -g
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man
PACKAGE=dircond
VERSION=3.0
DISTFILES=README COPYING NEWS ChangeLog Makefile $(SRCS) $(INCS) dircond.1
SRCS=dircond.c config.c event.c hashtab.c watcher.c pathdefn.c
OBJS=$(SRCS:.c=.o)
INCS=dircond.h
CPPFLAGS=-DVERSION=\"$(VERSION)\"

dircond: $(OBJS)
	cc -odircond $(CFLAGS) $(OBJS)

install-bin: dircond
	mkdir -p $(DESTDIR)$(BINDIR)
	cp dircond $(DESTDIR)$(BINDIR)

install-man: dircond.1
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	cp dircond.1 $(DESTDIR)$(MANDIR)/man1

install: install-bin install-man

distdir = $(PACKAGE)-$(VERSION)

distdir: $(DISTFILES)
	rm -rf $(distdir)
	mkdir $(distdir)
	cp $(DISTFILES) $(distdir)

dist: distdir
	tar cfz $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)

distcheck: distdir
	mkdir $(distdir)/_inst; \
	cd $(distdir) || exit 2;\
	make || exit 2; \
	make DESTDIR=`pwd`/_inst install || exit 2
	make dist

.PHONY: ChangeLog
ChangeLog:
	@if test -d .git; then                                               \
          git log --pretty='format:%ct  %an  <%ae>%n%n%s%n%n%b%n' |          \
            awk -f git2chg.awk > ChangeLog.tmp;                              \
          cmp ChangeLog ChangeLog.tmp > /dev/null 2>&1 ||                    \
            mv ChangeLog.tmp ChangeLog;                                      \
          rm -f ChangeLog.tmp;                                               \
        fi

clean:
	rm -f $(OBJS) dircond
