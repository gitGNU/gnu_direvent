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

/* A "post-init" variant of detach(), used on systems where the kqueue
   state cannot be inherited by the child process (most notably, Darwin).

   The function first performs a fork, then calls the init function, while
   still being connected to the controlling terminal and having the first
   three descriptors inherited from the parent process.  If the initialization
   succeeds, the child sends a SIGUSR1 to the parent, closes the first three
   descriptors and disconnects itself from the controlling terminal.
   Otherwise, it exits with a non-zero code. 

   The parent waits until a signal is delivered.  It exits successfully if
   delivered a SIGUSR1, and reports an error otherwise. */
   
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

static int lastsig;

void
catch_signal(int sig)
{
	lastsig = sig;
}

void
waitchild()
{
	while (lastsig == 0) 
		pause();
	
	if (lastsig == SIGUSR1)
		_exit(0);
	diag(LOG_CRIT, "failed to install watchers");
	exit(1);
}	

int
detach(void (*init)())
{
	static struct sigtab sigtab[] = {
		{ SIGHUP, SIG_IGN },
		{ SIGCHLD, catch_signal },
		{ SIGUSR1, catch_signal }
	};
	struct sigaction oldsa[NITEMS(sigtab)];
	pid_t pid;
	int ec;

	if (sigv_set_tab(NITEMS(sigtab), sigtab, oldsa))
		return -1;

	switch (fork()) {
	case -1:
		sigv_restore_tab(NITEMS(sigtab), sigtab, oldsa);
		return -1;
	case 0:
		break;
	default:
		waitchild();
	}

	init();
	kill(getppid(), SIGUSR1);
	
	pid = setsid();
	ec = errno;
	
	sigv_restore_tab(NITEMS(sigtab), sigtab, oldsa);
	
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
	
		
