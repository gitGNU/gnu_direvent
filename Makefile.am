# This file is part of Direvent -*- autoconf -*-
# Copyright (C) 2012-2014 Sergey Poznyakoff
#
# Direvent is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Direvent is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Direvent.  If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I am -I grecs/am

SUBDIRS= grecs src tests doc po

.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                   \
		git log --pretty='format:%ct  %an  <%ae>%n%n%s%n%n%b%n' |  \
		awk -f $(top_builddir)/grecs/build-aux/git2chg.awk > ChangeLog; \
        fi


EXTRA_DIST = build-aux/config.rpath
