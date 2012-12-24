# dircond - directory content watcher daemon
# Copyright (C) 2012 Sergey Poznyakoff
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

CFLAGS=-ggdb -Wall
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man
PACKAGE=dircond
VERSION=1.0
DISTFILES=Makefile dircond.c dlist.c dircond.1

dircond: dircond.c dlist.c
	cc -odircond $(CFLAGS) dircond.c

install-bin: dircond
	mkdir -p $(DESTDIR)$(BINDIR)
	cp dircond $(DESTDIR)$(BINDIR)

install-man:;
install-man: dircond.1
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	cp dircond.1 $(DESTDIR)$(MANDIR)/man1

install: install-bin install-man

distdir = $(PACKAGE)-$(VERSION)

distdir:
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
	(cd $(distdir)/_inst; find . -type f)|sort|cut -c2- | \
           cmp - instlist
	make dist

clean:
	rm -f dircond
