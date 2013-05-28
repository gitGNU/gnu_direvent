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
#include <stdarg.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>

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

int
trans_strtotok(struct transtab *tab, char *str, int *ret)
{
	for (; tab->name; tab++)
		if (strcmp(tab->name, str) == 0) {
			*ret = tab->tok;
			return 0;
		}
	return -1;
}

char *
trans_toktostr(struct transtab *tab, int tok)
{
	for (; tab->name; tab++)
		if (tab->tok == tok)
			return tab->name;
	return NULL;
}

char *
trans_toknext(struct transtab *tab, int tok, int *next)
{
	int i;
	
	for (i = *next; tab[i].name; i++)
		if (tab[i].tok & tok) {
			*next = i + 1;
			return tab[i].name;
		}
	*next = i;
	return NULL;
}

char *
trans_tokfirst(struct transtab *tab, int tok, int *next)
{
	*next = 0;
	return trans_toknext(tab, tok, next);
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

static int
membergid(gid_t gid, size_t gc, gid_t *gv)
{
	int i;
	for (i = 0; i < gc; i++)
		if (gv[i] == gid)
			return 1;
	return 0;
}

static void
get_user_groups(uid_t uid, size_t *pgidc, gid_t **pgidv)
{
	size_t gidc = 0, n = 0;
	gid_t *gidv = NULL;
	struct passwd *pw;
	struct group *gr;

	pw = getpwuid(uid);
	if (!pw) {
		diag(LOG_ERR, 0, "no used with UID %lu",
		     (unsigned long)uid);
		exit(2);
	}
	
	n = 32;
	gidv = ecalloc(n, sizeof(gidv[0]));
		
	gidv[0] = pw->pw_gid;
	gidc = 1;
	
	setgrent();
	while (gr = getgrent()) {
		char **p;
		for (p = gr->gr_mem; *p; p++)
			if (strcmp(*p, pw->pw_name) == 0) {
				if (n == gidc) {
					n += 32;
					gidv = erealloc(gidv,
							n * sizeof(gidv[0]));
				}
				if (!membergid(gr->gr_gid, gidc, gidv))
					gidv[gidc++] = gr->gr_gid;
			}
	}
	endgrent();
	*pgidc = gidc;
	*pgidv = gidv;
}

void
setuser(const char *user)
{
	struct passwd *pw;
	size_t gidc;
	gid_t *gidv;
		
	pw = getpwnam(user);
	if (!pw) {
		diag(LOG_CRIT, "getpwnam(%s): %s", user, strerror(errno));
		exit(2);
	}
	if (pw->pw_uid == 0)
		return;

	get_user_groups(pw->pw_uid, &gidc, &gidv);
	if (setgroups(gidc, gidv) < 0) {
		diag(LOG_CRIT, "setgroups: %s", strerror(errno));
		exit(2);
	}
	free(gidv);

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

void
ev_log(int flags, struct dirwatcher *dp)
{
	int i;
	char *p;
	
	if (debug_level > 0) {
		for (p = trans_tokfirst(evsys_transtab, flags, &i); p;
		     p = trans_toknext(evsys_transtab, flags, &i))
			debug(1, ("%s: %s", dp->dirname, p));
	}
}

void
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

/* Output a help summary. Return a code suitable for exit(2). */
int
help()
{
	printf("Usage: %s [OPTIONS] [CONFIG]\n", program_name);
	printf("OPTIONS are:\n\n");

	printf("   -d            increase debug verbosity\n");
	printf("   -F FACILITY   log under this syslog facility (default: daemon);\n");
	printf("                 use -F 0 to log to stderr instead\n");
        printf("   -f            run in the foreground\n");
        printf("   -L TAG        log with this syslog tag\n");
	printf("   -P FILE       write PID to FILE\n");
	printf("   -t            check configuration file for errors and exit\n");
	printf("   -u USER       run as this USER\n\n");

	printf("   -h            output this help summary\n");
        printf("   -V            print program version and exit\n\n");

	printf("Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
		
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


void
sie_init()
{
	int i;
	
	for (i = 0; i < sie_xlat[i].sie_mask; i++)
		defevt(trans_toktostr(sie_trans, sie_xlat[i].sie_mask),
		       &sie_xlat[i], 0);
}
	

int signo = 0;

void
sigmain(int sig)
{
	signo = sig;
	signal(sig, sigmain);
}

int
main(int argc, char **argv)
{
	int c;
	int opt_debug_level = 0;
	int opt_foreground = 0;
	char *opt_tag = NULL;
	char *opt_pidfile = NULL;
	char *opt_user = NULL;
	int lint_only = 0;
	
	set_program_name(argv[0]);
	tag = (char*) program_name;

	evsys_init();
	sie_init();
	
	while ((c = getopt(argc, argv, "dF:fhLP:tu:V")) != EOF) {
		switch (c) {
		case 'd':
			opt_debug_level++;
			break;
		case 'F':			
			opt_facility = get_facility(optarg);
			break;
		case 'f':
			opt_foreground++;
			break;
		case 'h':
			exit(help());
			break;
		case 'L':
			opt_tag = optarg;
			break;
		case 'P':
			opt_pidfile = optarg;
			break;
		case 't':
			lint_only = 1;
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
	if (lint_only)
		return 0;
	
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
	do {
		process_timeouts();
		process_cleanup(0);
	} while (evsys_select () == 0);

	diag(LOG_INFO, "stopped");

	return 0;
}
