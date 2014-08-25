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

AC_DEFUN([DEVT_CC_OPT],[
  m4_pushdef([devt_optname],translit($1,[-],[_]))
  AC_MSG_CHECKING(whether $CC accepts $1)
   devt_save_cc="$CC"
   CC="$CC $1"
   AC_TRY_RUN([int main() { return 0; }],
   [devt_cv_cc_]devt_optname=yes,
   [devt_cv_cc_]devt_optname=no,
   [devt_cv_cc_]devt_optname=no)
   CC="$devt_save_cc"
  AC_MSG_RESULT($[devt_cv_cc_]devt_optname)
  
  if test $[devt_cv_cc_]devt_optname = yes; then
         ifelse([$2],,:,[$2])
  ifelse([$3],,,else
         [$3])
  fi
  m4_popdef([devt_optname])
  ])

AC_DEFUN([DEVT_CC_OPT_CFLAGS],[
  DEVT_CC_OPT([$1],[CFLAGS="$CFLAGS $1"])
])
  
AC_DEFUN([DEVT_CC_PAREN_QUIRK],[
  DEVT_CC_OPT_CFLAGS([-Wno-parentheses])
])

