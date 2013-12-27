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

ACLOCAL_AMFLAGS = -I grecs/am

SUBDIRS=grecs src tests doc

.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                   \
		git log --pretty='format:%ct  %an  <%ae>%n%n%s%n%n%b%n' |  \
		awk -f $(top_builddir)/grecs/build-aux/git2chg.awk > ChangeLog; \
        fi

