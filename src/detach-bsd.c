/* direvent - directory content watcher daemon
   Copyright (C) 2012-2016 Sergey Poznyakoff

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

/* "Early-init" detach() for BSD systems. It uses rfork instead of fork
   to ensure the event queue is inherited by the child process.  According
   to the kqueue(2) manpage:

   The kqueue() system call creates a new kernel event queue and returns a
   descriptor.  The queue is not inherited by a child created with fork(2).
   However, if rfork(2) is called without the RFFDG flag, then the descrip-
   tor table is shared, which will allow sharing of the kqueue between two
   processes.
*/	

#include "direvent.h"
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL   "/dev/null"
#endif

int
detach(void (*init)())
{
	struct sigaction oldsa, sa;
	pid_t pid;
	int ec;

	init();
	
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;

	if (sigaction(SIGHUP, &sa, &oldsa))
		return -1;

	switch (rfork(RFPROC)) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		_exit(0);
	}

	pid = setsid();
	ec = errno;
	
	sigaction(SIGHUP, &oldsa, NULL);
	
	if (pid == -1) {
		errno = ec;
		return -1;
	}

	chdir("/");

	close(0);
	close(1);
	close(2);
	open(_PATH_DEVNULL, O_RDONLY);
	open(_PATH_DEVNULL, O_WRONLY);
	dup(1);

	return 0;
}
	
		
