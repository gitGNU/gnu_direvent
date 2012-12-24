CFLAGS=-ggdb -Wall
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man
PACKAGE=upev
VERSION=1.0
DISTFILES=Makefile dircond.c dlist.c

dircond: dircond.c dlist.c
	cc -odircond $(CFLAGS) dircond.c

install-bin: dircond
	mkdir -p $(DESTDIR)$(BINDIR)
	cp dircond $(DESTDIR)$(BINDIR)

install-man:;
#install-man: dircond.1
#	mkdir -p $(DESTDIR)$(MANDIR)/man1
#	cp dircond.1 $(DESTDIR)$(MANDIR)/man1

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
