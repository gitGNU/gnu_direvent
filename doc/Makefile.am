info_TEXINFOS=dircond.texi
dircond_TEXINFOS=\
 fdl.texi

dist_man_MANS=dircond.8 dircond.conf.5

EXTRA_DIST = \
 gendocs_template

clean-local:
	@rm -rf manual

GENDOCS=gendocs.sh 

TEXI2DVI=texi2dvi -t '@set $(RENDITION)' -E

.PHONY: manual
manual:
	TEXINPUTS=$(srcdir):$(top_srcdir)/build-aux:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(MAKEINFOFLAGS) $(AM_MAKEINFOFLAGS)" \
	 TEXI2DVI="$(TEXI2DVI)" \
         TEXI2HTML="texi2html $(AM_MAKEINFOFLAGS)" \
	 $(GENDOCS) --texi2html $(PACKAGE) '$(PACKAGE_NAME) manual'

manual.tar.bz2: manual
	tar cfj manual.tar.bz2 manual

man-tar: manual.tar.bz2
