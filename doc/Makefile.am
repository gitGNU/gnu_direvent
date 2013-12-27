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
