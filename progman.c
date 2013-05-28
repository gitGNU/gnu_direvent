/* dircond - directory content watcher daemon
   Copyright (C) 2012, 2013 Sergey Poznyakoff

   Dircond is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   Dircond is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with dircond. If not, see <http://www.gnu.org/licenses/>. */

#include "dircond.h"
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>

/* Process list */

/* Redirector codes */
#define REDIR_OUT 0
#define REDIR_ERR 1

/* A running process is described by this structure */
struct process {
	struct process *next, *prev;
	unsigned timeout;       /* Timeout in seconds */
	pid_t pid;              /* PID */
	time_t start;           /* Time when the process started */
	pid_t redir[2];         /* PIDs of redirector processes (0 if no
				   redirector) */
};

/* List of running processes */
struct process *proc_list;
/* List of available process slots */
struct process *proc_avail;

/* Declare functions for handling process lists */
struct process *
proc_unlink(struct process **root, struct process *p)
{
	if (p->prev)
		p->prev->next = p->next;
	else
		*root = p->next;
	if (p->next)
		p->next->prev = p->prev;
	p->next = p->prev = NULL;
	return p;
}

struct process *
proc_pop(struct process **pp)
{
	if (*pp)
		return proc_unlink(pp, *pp);
	return NULL;
}

void
proc_push(struct process **pp, struct process *p)
{
	p->prev = NULL;
	p->next = *pp;
	if (*pp)
		(*pp)->prev = p;
	*pp = p;
}


/* Process list handling (high-level) */

struct process *
register_process(pid_t pid, time_t t, unsigned timeout)
{
	struct process *p;

	if (proc_avail)
		p = proc_pop(&proc_avail);
	else
		p = emalloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	p->timeout = timeout;
	p->pid = pid;
	p->start = t;
	
	proc_push(&proc_list, p);
	return p;
}

void
deregister_process(pid_t pid, time_t t)
{
	struct process *p;

	for (p = proc_list; p; p = p->next)
		if (p->pid == pid) {
			if (p->prev)
				p->prev->next = p->next;
			else
				proc_list = p;
			if (p->next)
				p->next->prev = p->prev;
			free(p);
			break;
		}
}

struct process *
process_lookup(pid_t pid)
{
	struct process *p;

	for (p = proc_list; p; p = p->next)
		if (p->pid == pid)
			return p;
	return NULL;
}

static void
print_status(pid_t pid, int status, sigset_t *mask)
{
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 0)
			debug(1, ("process %lu exited successfully",
				  (unsigned long) pid));
		else
			diag(LOG_ERR, "process %lu failed with status %d",
			     (unsigned long) pid, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		int prio;

		if (sigismember(mask, WTERMSIG(status)))
			prio = LOG_DEBUG;
		else
			prio = LOG_ERR;

		diag(prio, "process %lu terminated on signal %d",
		     (unsigned long) pid, WTERMSIG(status));
	} else if (WIFSTOPPED(status))
		diag(LOG_ERR, "process %lu stopped on signal %d",
		     (unsigned long) pid, WSTOPSIG(status));
#ifdef WCOREDUMP
	else if (WCOREDUMP(status))
		diag(LOG_ERR,
		     "process %lu dumped core", (unsigned long) pid);
#endif
	else
		diag(LOG_ERR,
		     "process %lu terminated with unrecognized status",
		     (unsigned long) pid);
}

void
process_cleanup(int expect_term)
{
	pid_t pid;
	int status;
	
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		sigset_t set;
		struct process *p = process_lookup(pid);

		sigemptyset(&set);
		if (expect_term)
			sigaddset(&set, SIGTERM);
		if (!p) {
			sigaddset(&set, SIGTERM);
			sigaddset(&set, SIGKILL);
		}
		print_status(pid, status, &set);
		if (p) {
			if (p->redir[REDIR_OUT])
				kill(p->redir[REDIR_OUT], SIGKILL);
			if (p->redir[REDIR_ERR])
				kill(p->redir[REDIR_ERR], SIGKILL);
			p->pid = 0;
			proc_unlink(&proc_list, p);
			proc_push(&proc_avail, p);
		}
	}
}

void
process_timeouts()
{
	struct process *p;
	time_t now = time(NULL);
	time_t alarm_time = 0, x;

	debug(2, ("begin scanning process list"));
	for (p = proc_list; p; p = p->next) {
		x = now - p->start;
		if (x >= p->timeout) {
			diag(LOG_ERR, "process %lu timed out",
			     (unsigned long) p->pid);
			kill(p->pid, SIGKILL);
		} else if (alarm_time == 0 ||
			   p->timeout - x < alarm_time)
			alarm_time = p->timeout - x;
	}

	if (alarm_time) {
		debug(2, ("scheduling alarm in %lu seconds",
			  (unsigned long) alarm_time));
		alarm(alarm_time);
	}
	debug(2, ("end scanning process list"));
}

int
switchpriv(struct handler *hp)
{
	if (hp->uid == 0 || hp->uid == getuid())
		return 0;
	
	if (setgroups(hp->gidc, hp->gidv) < 0) {
		diag(LOG_CRIT, "setgroups: %s",
		     strerror(errno));
		return 1;
	}
	if (setregid(hp->gidv[0], hp->gidv[0]) < 0) {
		diag(LOG_CRIT, "setregid(%lu,%lu): %s",
		     (unsigned long) hp->gidv[0],
		     (unsigned long) hp->gidv[0],
		     strerror(errno));
		return 1;
	}
	if (setreuid(hp->uid, hp->uid) < 0) {
		diag(LOG_CRIT, "setreuid(%lu,%lu): %s",
		     (unsigned long) hp->uid,
		     (unsigned long) hp->uid,
		     strerror(errno));
		return 1;
	}
	return 0;
}		

typedef fd_set *bigfd_set;

#define BIGFD_SET_COUNT \
	((sysconf(_SC_OPEN_MAX) + FD_SETSIZE - 1) / FD_SETSIZE)

#define BIGFD_SET_ALLOC() \
	ecalloc(BIGFD_SET_COUNT, sizeof(fd_set))

#define BIGFD_ZERO(fds) \
	memset(fds, 0, sizeof(*bigfd_set) * BIGFD_SET_COUNT)
#define BIGFD_SET(n, fds) \
	FD_SET((n) % FD_SETSIZE, (fds) + (n) / FD_SETSIZE)
#define BIGFD_ISSET(n, fds) \
	FD_ISSET((n) % FD_SETSIZE, (fds) + (n) / FD_SETSIZE)

static void
close_fds(bigfd_set fdset)
{
	int i;

	for (i = sysconf(_SC_OPEN_MAX) - 1; i >= 0; i--) {
		if (fdset && BIGFD_ISSET(i, fdset))
			continue;
		close(i);
	}
}

/* Operations with handlers and redirections */

static void
redir_exit(int sig)
{
	_exit(0);
}

int
open_redirector(const char *tag, int prio, pid_t *return_pid)
{
	int p[2];
	FILE *fp;
	char buf[512];
	pid_t pid;
	bigfd_set fdset;

	if (pipe(p)) {
		diag(LOG_ERR,
		     "cannot start redirector for %s, pipe failed: %s",
		     tag, strerror(errno));
		return -1;
	}
	switch (pid = fork()) {
	case 0:
		/* Redirector process */
		fdset = BIGFD_SET_ALLOC();
		BIGFD_SET(p[0], fdset);
		if (facility <= 0)
			BIGFD_SET(2, fdset);
		close_fds(fdset);
		
		alarm(0);
		signal_setup(redir_exit);

		fp = fdopen(p[0], "r");
		if (fp == NULL)
			_exit(1);
		if (facility > 0) 
			openlog(tag, LOG_PID, facility);

		while (fgets(buf, sizeof(buf), fp) > 0) {
			int len = strlen(buf);
			if (len && buf[len-1] == '\n')
				buf[len-1] = 0;
			diag(prio, "%s", buf);
		}
		_exit(0);
      
	case -1:
		diag(LOG_CRIT,
		     "cannot run redirector `%s': fork failed: %s",
		     tag, strerror(errno));
		return -1;

	default:
		debug(1, ("redirector for %s started, pid=%lu",
			  tag, (unsigned long) pid));
		close(p[0]);
		*return_pid = pid;
		return p[1];
	}
}

static void
event_to_env(event_mask *event)
{
	char *p,*q;
	char buf[1024];
	int i;

	snprintf(buf, sizeof buf, "%d", event->sys_mask);
	setenv("DIRCOND_SYS_EVENT_CODE", buf, 1);
	q = buf;
	for (p = trans_tokfirst(evsys_transtab, event->sys_mask, &i); p;
	     p = trans_toknext(evsys_transtab, event->sys_mask, &i)) {
		if (q > buf)
			*q++ = ' ';
		while (*p)
			*q++ = *p++;
	}
	*q = 0;	
	if (q > buf)
		setenv("DIRCOND_SYS_EVENT", buf, 1);
	else
		unsetenv("DIRCOND_SYS_EVENT");
	p = trans_toktostr(sie_trans, event->sie_mask);
	if (p) {
		snprintf(buf, sizeof buf, "%d", event->sie_mask);
		setenv("DIRCOND_EVENT_CODE", buf, 1);
		setenv("DIRCOND_EVENT", p, 1);
	} else {
		unsetenv("DIRCOND_EVENT_CODE");
		unsetenv("DIRCOND_EVENT");
	}
}

int
run_handler(struct dirwatcher *dp, struct handler *hp, event_mask *event,
	    const char *file)
{
	pid_t pid;
	int redir_fd[2] = { -1, -1 };
	pid_t redir_pid[2];
	struct process *p;

	if (!hp->prog)
		return 0;
	if (access(hp->prog, X_OK)) {
		diag(LOG_ERR, "watchpoint %s: cannot execute %s: %s",
		     dp->dirname, hp->prog, strerror(errno));
		return 1;
	}
	
	debug(1, ("starting %s, dir=%s, file=%s", hp->prog, dp->dirname, file));
	if (hp->flags & HF_STDERR)
		redir_fd[REDIR_ERR] = open_redirector(hp->prog, LOG_ERR,
						      &redir_pid[REDIR_ERR]);
	if (hp->flags & HF_STDOUT)
		redir_fd[REDIR_OUT] = open_redirector(hp->prog, LOG_INFO,
						      &redir_pid[REDIR_OUT]);
	
	pid = fork();
	if (pid == -1) {
		close(redir_fd[REDIR_OUT]);
		close(redir_fd[REDIR_ERR]);
		diag(LOG_ERR, "fork: %s", strerror(errno));
		return -1;
	}
	
	if (pid == 0) {		
		/* child */
		char *argv[2];
		bigfd_set fdset = BIGFD_SET_ALLOC();
		
		if (switchpriv(hp))
			_exit(127);
		
		if (chdir(dp->dirname)) {
			diag(LOG_CRIT, "cannot change to %s: %s",
			     dp->dirname, strerror(errno));
			_exit(127);
		}

		if (redir_fd[REDIR_OUT] != -1) {
			if (redir_fd[REDIR_OUT] != 1 &&
			    dup2(redir_fd[REDIR_OUT], 1) == -1) {
				diag(LOG_ERR, "dup2: %s", strerror(errno));
				_exit(127);
			}
			BIGFD_SET(1, fdset);
		}
		if (redir_fd[REDIR_ERR] != -1) {
			if (redir_fd[REDIR_ERR] != 2 &&
			    dup2(redir_fd[REDIR_ERR], 2) == -1) {
				diag(LOG_ERR, "dup2: %s", strerror(errno));
				_exit(127);
			}
			BIGFD_SET(2, fdset);
		}
		close_fds(fdset);
		alarm(0);
		signal_setup(SIG_DFL);
		signal(SIGCHLD, SIG_DFL);
		argv[0] = (char*) hp->prog;
		argv[1] = NULL;
		event_to_env(event);
		if (file)
			setenv("DIRCOND_FILE", file, 1);
		execv(argv[0], argv);
		diag(LOG_ERR, "execv: %s: %s", argv[0], strerror(errno));
		_exit(127);
	}

	/* master */
	debug(1, ("%s running; dir=%s, file=%s, pid=%lu",
		  hp->prog, dp->dirname, file, (unsigned long)pid));

	p = register_process(pid, time(NULL), hp->timeout);
	
	memcpy(p->redir, redir_pid, sizeof(p->redir));
	
	close(redir_fd[REDIR_OUT]);
	close(redir_fd[REDIR_ERR]);

	if (hp->flags & HF_NOWAIT) {
		return 0;
	}

	debug(1, ("waiting for %s (%lu) to terminate",
		  hp->prog, (unsigned long)pid));
	while (time(NULL) - p->start < 2 * p->timeout) {
		sleep(1);
		process_cleanup(1);
		if (p->pid == 0)
			break;
	}
	return 0;
}
