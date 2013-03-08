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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "dircond.h"

#ifndef SYSCONFDIR
# define SYSCONFDIR "/etc/"
#endif

/* Configuration settings */
const char *program_name;         /* This program name */
const char *conffile = SYSCONFDIR "/dircond.conf";
int foreground;                   /* Remain in the foreground */
char *tag;                        /* Syslog tag */
int facility = -1;                /* Use this syslog facility for logging.
				     -1 means log to stderr */
int debug_level;                  /* Debug verbosity level */
char *pidfile = NULL;             /* Store PID to this file */
char *user = NULL;                /* User to run as */


/* Diagnostic functions */
const char *
severity(int prio)
{
	switch (prio) {
	case LOG_EMERG:
		return "EMERG";
	case LOG_ALERT:
		return "ALERT";
	case LOG_CRIT:
		return "CRIT";
	case LOG_ERR:
		return "ERROR";
	case LOG_WARNING:
		return "WARNING";
	case LOG_NOTICE:
		return "NOTICE";
	case LOG_INFO:
		return "INFO";
	case LOG_DEBUG:
		return "DEBUG";
	}
	return NULL;
}

void
vdiag(int prio, const char *fmt, va_list ap)
{
	const char *s;
	
	if (facility <= 0) {
		fprintf(stderr, "%s: ", program_name);
		s = severity(prio);
		if (s)
			fprintf(stderr, "[%s] ", s);
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	} else {
		vsyslog(prio, fmt, ap);
	}
}

void
diag(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdiag(prio, fmt, ap);
	va_end(ap);
}
	
void
debugprt(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdiag(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

/* Memory allocation with error checking */
void *
emalloc(size_t size)
{
	void *p = malloc(size);
	if (!p) {
		diag(LOG_CRIT, "not enough memory");
		exit(2);
	}
	return p;
}

void *
ecalloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (!p) {
		diag(LOG_CRIT, "not enough memory");
		exit(2);
	}
	return p;
}

void *
erealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (!p) {
		diag(LOG_CRIT, "not enough memory");
		exit(2);
	}
	return p;
}

char *
estrdup(const char *str)
{
	size_t len = strlen(str);
	char *p = emalloc(len + 1);
	memcpy(p, str, len);
	p[len] = 0;
	return p;
}

/* Create a full file name from directory and file name */
char *
mkfilename(const char *dir, const char *file)
{
	char *tmp;
	size_t dirlen = strlen(dir);
	size_t fillen = strlen(file);
	size_t len;

	while (dirlen > 0 && dir[dirlen-1] == '/')
		dirlen--;

	len = dirlen + (dir[0] ? 1 : 0) + fillen;
	tmp = malloc(len + 1);
	if (tmp) {
		memcpy(tmp, dir, dirlen);
		if (dir[0])
			tmp[dirlen++] = '/';
		memcpy(tmp + dirlen, file, fillen);
		tmp[len] = 0;
	}
	return tmp;
}

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

/* Command line processing and auxiliary functions */

static void
set_program_name(const char *arg)
{
	char *p = strrchr(arg, '/');
	if (p)
		program_name = p + 1;
	else
		program_name = arg;
}


void
signal_setup(void (*sf) (int))
{
	signal(SIGTERM, sf);
	signal(SIGQUIT, sf);
	signal(SIGINT, sf);
	signal(SIGHUP, sf);
	signal(SIGALRM, sf);
	signal(SIGUSR1, sf);
	signal(SIGUSR2, sf);
}

static void
close_fds(fd_set *fdset)
{
	int i;

	for (i = sysconf(_SC_OPEN_MAX) - 1; i >= 0; i--) {
		if (fdset && FD_ISSET(i, fdset))
			continue;
		close(i);
	}
}

void
storepid(const char *pidfile)
{
	FILE *fp = fopen(pidfile, "w");
	if (!fp) {
		diag(LOG_ERR, "cannot open pidfile %s for writing: %s",
		     pidfile, strerror(errno));
	} else {
		fprintf(fp, "%lu\n", (unsigned long) getpid());
		fclose(fp);
	}
}

void
setuser(const char *user)
{
	struct passwd *pw;

	pw = getpwnam(user);
	if (!pw) {
		diag(LOG_CRIT, "getpwnam(%s): %s", user, strerror(errno));
		exit(2);
	}
	if (pw->pw_uid == 0)
		return;
	if (setgid(pw->pw_gid)) {
		diag(LOG_CRIT, "setgid(%lu): %s", (unsigned long) pw->pw_gid,
		     strerror(errno));
		exit(2);
	}
	if (setuid(pw->pw_uid)) {
		diag(LOG_CRIT, "setuid(%lu): %s", (unsigned long) pw->pw_uid,
		     strerror(errno));
		exit(2);
	}
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
	fd_set fdset;

	if (pipe(p)) {
		diag(LOG_ERR,
		     "cannot start redirector for %s, pipe failed: %s",
		     tag, strerror(errno));
		return -1;
	}
	switch (pid = fork()) {
	case 0:
		/* Redirector process */
		FD_ZERO(&fdset);
		FD_SET(p[0], &fdset);
		if (facility <= 0)
			FD_SET(2, &fdset);
		close_fds(&fdset);
		
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
		close (p[0]);
		*return_pid = pid;
		return p[1];
	}
}

static int
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

static int
run_handler(struct dirwatcher *dp, struct handler *hp, int event,
	    const char *file)
{
	pid_t pid;
	char buf[1024];
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
		fd_set fdset;

		if (switchpriv(hp))
			_exit(127);
		
		if (chdir(dp->dirname)) {
			diag(LOG_CRIT, "cannot change to %s: %s",
			     dp->dirname, strerror(errno));
			_exit(127);
		}

		FD_ZERO(&fdset);

		if (redir_fd[REDIR_OUT] != -1) {
			if (redir_fd[REDIR_OUT] != 1 &&
			    dup2(redir_fd[REDIR_OUT], 1) == -1) {
				diag(LOG_ERR, "dup2: %s", strerror(errno));
				_exit(127);
			}
			FD_SET(1, &fdset);
		}
		if (redir_fd[REDIR_ERR] != -1) {
			if (redir_fd[REDIR_ERR] != 2 &&
			    dup2(redir_fd[REDIR_ERR], 2) == -1) {
				diag(LOG_ERR, "dup2: %s", strerror(errno));
				_exit(127);
			}
			FD_SET(2, &fdset);
		}
		close_fds(&fdset);
		alarm(0);
		signal_setup(SIG_DFL);
		signal(SIGCHLD, SIG_DFL);
		argv[0] = (char*) hp->prog;
		argv[1] = NULL;
		snprintf(buf, sizeof buf, "%d", event);
		setenv("DIRCOND_EVENT_CODE", buf, 1);
		setenv("DIRCOND_EVENT", ev_code_to_name(event), 1);
		if (file)
			setenv("DIRCOND_FILE", file, 1);
		execv(argv[0], argv);
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

/* Output a help summary. Return a code suitable for exit(2). */
int
help()
{
	printf("Usage: %s [OPTIONS] [CONFIG]\n", program_name);
	printf("OPTIONS are:\n\n");

	printf("   -d            increase debug verbosity\n");
        printf("   -f            run in the foreground\n");
	printf("   -F FACILITY   log under this syslog facility (default: daemon);\n");
	printf("                 use -F 0 to log to stderr instead\n");
	printf("   -P FILE       write PID to FILE\n");
        printf("   -t TAG        log with this syslog tag\n");
	printf("   -u USER       run as this USER\n\n");

	printf("   -h            output this help summary\n");
        printf("   -V            print program version and exit\n\n");

	printf("Report bugs to <gray+dircond@gnu.org.ua>.\n");
		
	return 0;
}

static char license[] = "\
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n";

int
version()
{
	printf("dircond %s\n", VERSION);
	printf("Copyright (C) 2012, 2013 Sergey Poznyakoff\n");
	printf("%s\n", license);
	return 0;
}

int
get_facility(const char *arg)
{
	int f;
	
	if (read_facility(arg, &f)) {
		switch (errno) {
		case EINVAL:
			diag(LOG_CRIT,
			     "unknown syslog facility: %s", arg);
			break;

		case ERANGE:
			diag(LOG_CRIT, "syslog facility out of range");
			break;
				
		default:
			abort();
		}
		exit(1);
	}
	return f;
}

static void
process_event(struct inotify_event *ep)
{
	struct dirwatcher *dp;
	struct handler *h;
				
	dp = dirwatcher_lookup_wd(ep->wd);
	if (ep->mask & IN_IGNORED)
		return;
	else if (ep->mask & IN_Q_OVERFLOW) {
		diag(LOG_NOTICE,
		     "event queue overflow");
		return;
	} else if (ep->mask & IN_UNMOUNT) {
		/* FIXME: not sure if there's
		   anything to do. Perhaps we should
		   deregister the watched dirs that
		   were located under the mountpoint
		*/
		return;
	} else if (!dp) {
		if (ep->name)
			diag(LOG_NOTICE, "unrecognized event %x"
			     "for %s", ep->mask, ep->name);
		else
			diag(LOG_NOTICE,
			     "unrecognized event %x", ep->mask);
		return;
	} else if (ep->mask & IN_CREATE) {
		debug(1, ("%s/%s created", dp->dirname, ep->name));
		check_new_watcher(dp->dirname, ep->name);
	} else if (ep->mask & (IN_DELETE|IN_MOVED_FROM)) {
		debug(1, ("%s/%s deleted", dp->dirname, ep->name));
		remove_watcher(dp->dirname, ep->name);
	}

	ev_log(ep, dp);
	
	for (h = dp->handler_list; h; h = h->next) {
		if (h->ev_mask & ep->mask)
			run_handler(dp, h, ep->mask, ep->name);
	}
}	

int signo = 0;

void
sigmain(int sig)
{
	signo = sig;
	signal(sig, sigmain);
}

char buffer[4096];

int ifd;

int
main(int argc, char **argv)
{
	int c;
	int opt_debug_level = 0;
	int opt_foreground = 0;
	char *opt_tag = NULL;
	char *opt_pidfile = NULL;
	char *opt_user = NULL;
	
	set_program_name(argv[0]);
	tag = (char*) program_name;

	ifd = inotify_init();
	if (ifd == -1) {
		diag(LOG_CRIT, "inotify_init: %s", strerror(errno));
		exit(1);
	}

	while ((c = getopt(argc, argv, "dF:fhP:u:V")) != EOF) {
		switch (c) {
		case 'd':
			opt_debug_level++;
			break;
		case 'f':
			opt_foreground++;
			break;
		case 'h':
			exit(help());
			break;
		case 't':
			opt_tag = optarg;
			break;
		case 'F':			
			opt_facility = get_facility(optarg);
			break;
		case 'P':
			opt_pidfile = optarg;
			break;
		case 'u':
			opt_user = optarg;
			if (!getpwnam(opt_user)) {
				diag(LOG_CRIT, "no such user: %s", opt_user);
				exit(1);
			}
			break;
		case 'V':
			exit(version());
		default:
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	switch (argc) {
	default:
		diag(LOG_CRIT, "too many arguments");
		exit(1);
	case 1:
		conffile = argv[0];
		break;
	case 0:
		break;
	}

	config_parse(conffile);

	if (opt_debug_level)
		debug_level += opt_debug_level;
	if (opt_foreground)
		foreground = opt_foreground;
	if (opt_tag)
		tag = opt_tag;
	if (opt_pidfile)
		pidfile = opt_pidfile;
	if (opt_facility != -1)
		facility = opt_facility;
	if (opt_user)
		user = opt_user;
	
	setup_watchers();
	
	/* Become a daemon */
	if (!foreground) {
		if (daemon(0, 0)) {
			diag(LOG_CRIT, "daemon: %s", strerror(errno));
			exit(1);
		}
		if (facility <= 0)
			facility = LOG_DAEMON;
	}
	
	if (facility > 0)
		openlog(tag, LOG_PID, facility);

	diag(LOG_INFO, "started");

	/* Write pidfile */
	if (pidfile)
		storepid(pidfile);

	/* Relinquish superuser privileges */
	if (user && getuid() == 0)
		setuser(user);

	signal_setup(sigmain);
	signal(SIGCHLD, sigmain);
	
	/* Main loop */
	while (1) {
		struct inotify_event *ep;
		size_t size;
		ssize_t rdbytes;

		process_timeouts();
		process_cleanup(0);

		rdbytes = read(ifd, buffer, sizeof(buffer));
		if (rdbytes == -1) {
			if (errno == EINTR) {
				if (signo == SIGCHLD || signo == SIGALRM)
					continue;
				diag(LOG_NOTICE, "got signal %d", signo);
				break;
			}
			
			diag(LOG_NOTICE, "read failed: %s", strerror(errno));
			break;
		}
		
		ep = (struct inotify_event *) buffer;
		while (rdbytes) {
			if (ep->wd >= 0)
				process_event(ep);
			size = sizeof(*ep) + ep->len;
			ep = (struct inotify_event *) ((char*) ep + size);
			rdbytes -= size;
		}
	}
	diag(LOG_INFO, "stopped");

	return 0;
}
