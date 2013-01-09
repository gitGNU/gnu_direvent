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
#include <sys/inotify.h>
#include <sys/wait.h>
#include <sys/stat.h>

/* Configuration settings */
const char *program_name;         /* This program name */
int foreground;                   /* Remain in the foreground */
const char *tag;                  /* Syslog tag */
int facility = LOG_DAEMON;        /* Use this syslog facility for logging.
				     -1 means log to stderr */
int debug_level;                  /* Debug verbosity level */
unsigned handler_timeout = 5;     /* Timeout for handler program (seconds) */
int autowatch;                    /* Automatically add directories created
				     under watchpoints to the watcher. If set
				     to -1, nesting level is not limited. If
				     set to a positive value, this value limits
				     the nesting depth. */
char *pidfile = NULL;             /* Store PID to this file */
char *user = NULL;                /* User to run as */

/* Event codes */
enum {
	evt_create,                  /* file has been created */ 
	evt_delete,                  /* file has been deleted or moved out */
	evt_close,                   /* file has been modified and closed
					or moved in */
	evt_max                      /* number of handled events */
};

char *evtstr[] = { "create", "delete", "close" };

/* Handler flags. */
#define HF_NOWAIT 0x01       /* Don't wait for termination */
#define HF_STDOUT 0x02       /* Capture stdout */
#define HF_STDERR 0x04       /* Capture stderr */

/* Handler structure */
struct handler {
	int flags;           /* Handler flags */
	const char *prog;    /* Handler program (no arguments allowed) */
	unsigned timeout;    /* Handler timeout */
};

/* A directory watcher is described by the following structure */
struct dirwatcher {
	struct dirwatcher *next, *prev;
	struct dirwatcher *parent;        /* Points to the parent watcher.
					     NULL for top-level watchers */
	char *name;                       /* Pathname being watched */
	int wd;                           /* Watch descriptor */
	struct handler handler[evt_max];  /* Handlers */
};

/* Array of handlers for each event */
struct handler handler[evt_max];

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
#define LIST process
#define LIST_PUSH proc_push
#define LIST_POP proc_pop
#define LIST_UNLINK proc_unlink
#include "dlist.c"

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
	
static void
debugprt(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdiag(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

#define debug(l, c) do { if (debug_level>=(l)) debugprt c; } while(0)

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

static int
read_facility(const char *arg)
{
	static struct transtab { int f; char *s; } ftab[] = {
		{ LOG_AUTH, "auth" },
		{ LOG_AUTHPRIV, "authpriv" },
		{ LOG_CRON, "cron" },
		{ LOG_DAEMON, "daemon" },
		{ LOG_FTP, "ftp" },
		{ LOG_LOCAL0, "local0" },
		{ LOG_LOCAL1, "local1" },
		{ LOG_LOCAL2, "local2" },
		{ LOG_LOCAL3, "local3" },
		{ LOG_LOCAL4, "local4" },
		{ LOG_LOCAL5, "local5" },
		{ LOG_LOCAL6, "local6" },
		{ LOG_LOCAL7, "local7" },
		{ LOG_LPR, "lpr" },
		{ LOG_MAIL, "mail" },
		{ LOG_NEWS, "news" },
		{ LOG_USER, "user" },
		{ LOG_UUCP, "uucp" },
		{ 0, NULL }
	};
	struct transtab *p;
	char *s;
	unsigned long n;
	
	for (p = ftab; p->s; p++) {
		if (strcmp(p->s, arg) == 0)
			return p->f;
	}
	n = strtoul(arg, &s, 10);
	if (*s) {
		diag(LOG_CRIT, "unknown facility: %s", arg);
		exit(1);
	}
	if (n > 256) {
		diag(LOG_CRIT, "facility out of range: %s", arg);
		exit(1);
	}
	return n;
}

void
set_handler(const char *arg)
{
	int len;
	int n;

	/* Event code */
	len = strcspn(arg, ",:");
	for (n = 0; n < evt_max; n++)
		if (strncmp(arg, evtstr[n], len) == 0)
			break;

	if (n == evt_max) {
		char *p;
		n = strtoul(arg, &p, 10);
		if (*p || !(n >= 0 && n < evt_max)) {
			diag(LOG_CRIT, "unrecognized event: %*.*s",
			     len, len, arg);
			exit(1);
		}
	}

	/* flag */
	handler[n].flags = 0;
	handler[n].timeout = handler_timeout;
	
	for (arg += len; *arg == ','; arg += len) {
		++arg;
		len = strcspn(arg, ",:");
		if (arg[len] == 0)
			break;
		if (strncmp(arg, "wait", len) == 0)
			handler[n].flags &= ~HF_NOWAIT;
		else if (strncmp(arg, "nowait", len) == 0)
			handler[n].flags |= HF_NOWAIT;
		else if (strncmp(arg, "stdout", len) == 0)
			handler[n].flags |= HF_STDOUT;
		else if (strncmp(arg, "stderr", len) == 0)
			handler[n].flags |= HF_STDERR;
		else {
			diag(LOG_CRIT, "unknown flag %*.*s", len, len, arg);
			exit(1);
		}
	}

	if (*arg != ':') {
		diag(LOG_CRIT,
		     "bad handler specification near %s",
		     *arg ? arg : "end");
		exit(1);
	}
	++arg;
	
	handler[n].prog = (*arg == 0) ? NULL : arg;
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
print_status(pid_t pid, int status, int expect_term)
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

		if (expect_term && WTERMSIG(status) == SIGTERM)
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
		struct process *p = process_lookup(pid);
		print_status(pid, status, expect_term);
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
run_handler(struct dirwatcher *dp, int event, const char *file)
{
	pid_t pid;
	char buf[1024];
	int redir_fd[2] = { -1, -1 };
	pid_t redir_pid[2];
	struct process *p;
	struct handler *hp = &dp->handler[event];

	if (!hp->prog)
		return 0;

	debug(1, ("starting %s, dir=%s, file=%s", hp->prog, dp->name, file));
	if (hp->flags & HF_STDERR)
		redir_fd[REDIR_ERR] = open_redirector(hp->prog, LOG_INFO,
						      &redir_pid[REDIR_ERR]);
	if (hp->flags & HF_STDOUT)
		redir_fd[REDIR_OUT] = open_redirector(hp->prog, LOG_ERR,
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

		if (chdir(dp->name)) {
			diag(LOG_CRIT, "cannot change to %s: %s",
			     dp->name, strerror(errno));
			exit(1);
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
		setenv("DIRCOND_EVENT", evtstr[event], 1);
		if (file)
			setenv("DIRCOND_FILE", file, 1);
		execv(argv[0], argv);
		_exit(127);
	}

	/* master */
	debug(1, ("%s running; dir=%s, file=%s, pid=%lu",
		  hp->prog, dp->name, file, (unsigned long)pid));

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

			
/* Directory watcher functions */

/* A doubly-linked list of active watchers */
struct dirwatcher *dirwatcher_list;
/* Declare low-level functions for handling the watchers list */
#define LIST dirwatcher
#define LIST_PUSH dirwatcher_push
#define LIST_POP dirwatcher_pop
#define LIST_UNLINK dirwatcher_unlink
#include "dlist.c"

/* Free the allocated watcher (must have been unlinked from the list first) */
void
dirwatcher_free(struct dirwatcher *dwp)
{
	free(dwp->name);
	free(dwp);
}

/* Create a new watcher and attach it to the list. */
struct dirwatcher *
dirwatcher_create(int ifd, const char *name)
{
	struct dirwatcher *dwp;
	int wd;

	debug(1, ("creating watcher %s", name));
	dwp = malloc(sizeof(*dwp));
	if (!dwp) {
		diag(LOG_ERR, "not enough memory");
		return NULL;
	}
	dwp->name = strdup(name);
	if (!dwp->name) {
		diag(LOG_ERR, "not enough memory");
		free(dwp);
		return NULL;
	}
	dwp->parent = NULL;
	
	wd = inotify_add_watch(ifd, name,
			       IN_DELETE|IN_CREATE|IN_CLOSE_WRITE|
		               IN_MOVED_FROM|IN_MOVED_TO);
	if (wd == -1) {
		diag(LOG_ERR, "cannot set watch on %s: %s",
		     name, strerror(errno));
		dirwatcher_free(dwp);
		return NULL;
	}
	
	dwp->wd = wd;
	dirwatcher_push(&dirwatcher_list, dwp);
	
	return dwp;
}

/* Destroy a watcher, unlink it and reclaim the allocated memory. */
void
dirwatcher_destroy(int ifd, struct dirwatcher *dwp)
{
	debug(1, ("removing watcher %s", dwp->name));
	dirwatcher_unlink(&dirwatcher_list, dwp);
	inotify_rm_watch(ifd, dwp->wd);
	dirwatcher_free(dwp);
}

/* Find a watcher with the given descriptor */
struct dirwatcher *
dirwatcher_find_wd(int wd)
{
	struct dirwatcher *dwp;
	
	for (dwp = dirwatcher_list; dwp; dwp = dwp->next)
		if (dwp->wd == wd)
			break;
	return dwp;
}

/* Find a watcher with the given pathname */
struct dirwatcher *
dirwatcher_find_name(const char *name)
{
	struct dirwatcher *dwp;
	
	for (dwp = dirwatcher_list; dwp; dwp = dwp->next)
		if (strcmp(dwp->name, name) == 0)
			break;
	return dwp;
}

/* Compare full pathname with a directory and file name.  Return
   semantics is the same as in strcmp(2). */
int
name2cmp(const char *pathname, const char *dir, const char *name)
{
	int c;
	
	for (; *pathname && *dir; pathname++, dir++)
		if (c = *pathname - *dir)
			return c;
	while (*pathname && *pathname == '/')
		++pathname;
	while (*dir && *dir == '/')
		++dir;
	if (*dir)
		return - *dir;

	for (; *pathname && *name; pathname++, name++)
		if (c = *pathname - *name)
			return c;
	if (*pathname)
		return *pathname;
	if (*name)
		return - *name;
	return 0;
}

/* Remove a watcher identified by its directory and file name */
void
remove_watcher(int ifd, const char *dir, const char *name)
{
	struct dirwatcher *dwp;
	for (dwp = dirwatcher_list; dwp; dwp = dwp->next)
		if (name2cmp(dwp->name, dir, name) == 0) {
			dirwatcher_destroy(ifd, dwp);
			return;
		}
}

/* Return nesting level of a watcher */
int
dirlevel(struct dirwatcher *dw)
{
	int lev = 0;
	while (dw = dw->parent)
		++lev;
	return lev;
}

/* Check if a new watcher must be created and create it if so.

   A watcher must be created if (1) autowatch has negative value,
   or (2) it has a positive value and the nesting level of the parent
   watcher does not exceed it.

   Return 0 on success, -1 on error.
*/
int
check_new_watcher(int ifd, const char *dir, const char *name)
{
	int rc;
	char *fname;
	struct stat st;
	struct dirwatcher *parent;

	if (autowatch == 0)
		return 0;
	parent = dirwatcher_find_name(dir);
	if (autowatch > 0 && dirlevel(parent) >= autowatch)
		return 0;
	
	fname = mkfilename(dir, name);
	if (!fname) {
		diag(LOG_ERR, "cannot create watcher %s/%s: not enough memory",
		     dir, name);
		return -1;
	}

	if (stat(fname, &st)) {
		diag(LOG_ERR, "cannot create watcher %s/%s, stat failed: %s",
		     dir, name, strerror(errno));
		rc = -1;
	} else if (S_ISDIR(st.st_mode)) {
		struct dirwatcher *dwp = dirwatcher_create(ifd, fname);
		if (dwp) {
			rc = 0;
			dwp->parent = parent;
			memcpy(dwp->handler, parent->handler,
			       sizeof(dwp->handler));
		} else
			rc = -1;
	} else
		rc = 0;
	free(fname);
	return rc;
}

/* Output a help summary. Return a code suitable for exit(2). */
int
help()
{
	printf("Usage: %s [OPTIONS] DIR [DIR...]\n", program_name);
	printf("OPTIONS are:\n\n");

	printf("   -a            automatically watch created directories\n");
	printf("   -d            increase debug verbosity\n");
        printf("   -f            run in the foreground\n");
	printf("   -F FACILITY   log under this syslog facility\n");
	printf("   -l N          automatically watch new directories located\n");
	printf("                 up to Nth nesting level\n");
	printf("   -P FILE       write PID to FILE\n");
	printf("   -p EVENT,[FLAG[,FLAG...],]COMMAND\n");
	printf("                 start COMMAND upon EVENT\n");
	printf("   -T TIMEOUT    set timeout for external commands\n");
        printf("   -t TAG        log with this syslog tag\n");
	printf("   -u USER       run as this USER\n");
		   
	printf("   -h            output this help summary\n\n");
	printf("Report bugs to <gray+dircond@gnu.org.ua>.\n");
		
	return 0;
}

int signo = 0;

void
sigmain(int sig)
{
	signo = sig;
	signal(sig, sigmain);
}

char buffer[4096];

static void
parse_options (int argc, char **argv)
{
	int c;

	optind = 0;
	while ((c = getopt(argc, argv, "+adF:fhl:P:p:T:t:u:")) != EOF) {
		switch (c) {
		case 'a':
			autowatch = -1;
			break;
		case 'd':
			debug_level++;
			break;
		case 'f':
			foreground++;
			break;
		case 'h':
			exit(help());
			break;
		case 'l':
			autowatch = atoi(optarg);
			break;
		case 'T':
			handler_timeout = atoi(optarg);
			break;
		case 't':
			tag = optarg;
			break;
		case 'F':
			facility = read_facility(optarg);
			break;
		case 'P':
			pidfile = optarg;
			break;
		case 'p':
			set_handler(optarg);
			break;
		case 'u':
			user = optarg;
			if (!getpwnam(user)) {
				diag(LOG_CRIT, "no such user: %s", user);
				exit(1);
			}
			break;
		default:
			exit(1);
		}
	}
}

int
main(int argc, char **argv)
{
	int ifd, c, i;
	struct dirwatcher *dp;
	
	set_program_name(argv[0]);
	tag = program_name;

	ifd = inotify_init();
	if (ifd == -1) {
		diag(LOG_CRIT, "inotify_init: %s", strerror(errno));
		exit(1);
	}

	while (1) {
		parse_options (argc, argv);
		argc -= optind;
		argv += optind;
		if (!argc)
			break;
		for (i = 0; i < argc; i++) {
			struct dirwatcher *dwp;
			
			if (argv[i][0] == '-')
				break;
			dwp = dirwatcher_create(ifd, argv[i]);
			if (!dwp) {
				diag(LOG_CRIT,
				     "cannot create watcher; exiting");
				exit(1);
			}
			memcpy(dwp->handler, handler, sizeof (dwp->handler));
		}
		argc -= i - 1;
		if (argc == 1)
			break;
		argv += i - 1;
		argv[0] = (char*) program_name;
	}

	if (!dirwatcher_list) {
		diag(LOG_CRIT, "not enough arguments");
		exit(1);
	}
	
	/* Become a daemon */
	if (!foreground) {
		if (daemon(0, 0)) {
			diag(LOG_CRIT, "daemon: %s", strerror(errno));
			exit(1);
		}
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
			if (ep->wd >= 0) {
				int ev = -1;
				dp = dirwatcher_find_wd(ep->wd);
				if (ep->mask & IN_IGNORED)
					/* nothing */;
				else if (ep->mask & IN_Q_OVERFLOW)
					diag(LOG_NOTICE,
					     "event queue overflow");
				else if (ep->mask & IN_UNMOUNT)
					/* FIXME: not sure if there's
					   anything to do. Perhaps we should
					   deregister the watched dirs that
					   were located under the mountpoint
					*/;
				else if (!dp) {
					if (ep->name)
						diag(LOG_NOTICE,
						     "unrecognized event %x"
						     "for %s", ep->mask,
						     ep->name);
					else
						diag(LOG_NOTICE,
						     "unrecognized event %x",
						     ep->mask);
				} else if (ep->mask & IN_CREATE) {
					ev = evt_create;
					debug(1, ("%s/%s created",
						  dp->name, ep->name));
					check_new_watcher(ifd,
							  dp->name, ep->name);
				} else if (ep->mask & (IN_DELETE|
						       IN_MOVED_FROM)) {
					ev = evt_delete;
					debug(1, ("%s/%s deleted",
						  dp->name, ep->name));
					remove_watcher(ifd, dp->name,
						       ep->name);
				} else if (ep->mask & (IN_CLOSE_WRITE|
						       IN_MOVED_TO)) {
					ev = evt_close;
					debug(1, ("%s/%s written",
						  dp->name, ep->name));
				} else
					diag(LOG_NOTICE,
					     "%s/%s: unexpected event %x",
					     dp->name, ep->name, ep->mask);

				if (ev >= 0 && ev < evt_max) {
					run_handler(dp, ev, ep->name);
				}
			}
			size = sizeof(*ep) + ep->len;
			ep = (struct inotify_event *) ((char*) ep + size);
			rdbytes -= size;
		}
	}
	diag(LOG_INFO, "stopped");

	return 0;
}
