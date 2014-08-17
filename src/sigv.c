/* direvent - directory content watcher daemon
   Copyright (C) 2012-2014 Sergey Poznyakoff

   Direvent is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   Direvent is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with direvent. If not, see <http://www.gnu.org/licenses/>. */

#include "direvent.h"

int
sigv_set_action(int sigc, int *sigv, struct sigaction *sa)
{
	int i;
	
	for (i = 0; i < sigc; i++) {
		if (sigaction(sigv[i], &sa[i], NULL))
			return i+1;
	}
	return 0;
}

int
sigv_restore_tab(int sigc, struct sigtab *sigtab, struct sigaction *sa)
{
	int i;
	
	for (i = 0; i < sigc; i++) {
		if (sigaction(sigtab[i].signo, &sa[i], NULL))
			return i+1;
	}
	return 0;
}
	
int
sigv_set_all(void (*handler)(int), int sigc, int *sigv,
	     struct sigaction *retsa)
{
	int i;
	struct sigaction sa;
	
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	
	for (i = 0; i < sigc; i++) {
		sa.sa_handler = handler;
		
		if (sigaction(sigv[i], &sa, retsa ? &retsa[i] : NULL)) {
			if (retsa) {
				int ec = errno;
				sigv_set_action(i, sigv, retsa);
				errno = ec;
			}
			return -1;
		}
	}
	return 0;
}

int
sigv_set_tab(int sigc, struct sigtab *sigtab, struct sigaction *retsa)
{
	int i;
	struct sigaction sa;
	
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	
	for (i = 0; i < sigc; i++) {
		sa.sa_handler = sigtab[i].sigfun;
		
		if (sigaction(sigtab[i].signo, &sa,
			      retsa ? &retsa[i] : NULL)) {
			if (retsa) {
				int ec = errno;
				sigv_restore_tab(i, sigtab, retsa);
				errno = ec;
			}
			return -1;
		}
	}
	return 0;
}
