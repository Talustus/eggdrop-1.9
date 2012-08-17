dnl config.m4
dnl
dnl Copyright (C) 2004 Eggheads Development Team
dnl
dnl This program is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU General Public License
dnl as published by the Free Software Foundation; either version 2
dnl of the License, or (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
dnl
dnl $Id: config.m4,v 1.2 2004/06/16 06:33:45 wcc Exp $
dnl

EGG_MODULE_START(perlscript, [perl support], "yes")

AC_PATH_PROG(perlcmd, perl)
PERL_LDFLAGS=`$perlcmd -MExtUtils::Embed -e ldopts 2>/dev/null`

if test "${PERL_LDFLAGS+set}" != "set"; then
  AC_MSG_WARN([

  Your system does not provide a working perl environment. The
  perlscript module will therefore be disabled.

  ])
  EGG_MOD_ENABLED="no"
else
  PERL_CCFLAGS=`$perlcmd -MExtUtils::Embed -e ccopts 2>/dev/null`
  egg_perlscript="yes"
  AC_SUBST(PERL_LDFLAGS)
  AC_SUBST(PERL_CCFLAGS)
fi

EGG_MODULE_END()
