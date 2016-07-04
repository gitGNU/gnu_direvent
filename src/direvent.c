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

#include "direvent.h"
#include <stdarg.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <grecs.h>
#include <locale.h>
#include "wordsplit.h"

#ifndef SYSCONFDIR
# define SYSCONFDIR "/etc"
#endif
#define DEFAULT_CONFFILE SYSCONFDIR "/direvent.conf"

/* Configuration settings */
const char *program_name;         /* This program name */
const char *conffile = DEFAULT_CONFFILE;
int foreground;                   /* Remain in the foreground */
char *self_test_prog;
char *tag;                        /* Syslog tag */
int facility = -1;                /* Use this syslog facility for logging.
				     -1 means log to stderr */
int syslog_include_prio;
int debug_level;                  /* Debug verbosity level */
char *pidfile = NULL;             /* Store PID to this file */
char *user = NULL;                /* User to run as */

int log_to_stderr = LOG_DEBUG;


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
	va_list tmp;
	
	if (log_to_stderr >= prio) {
		fprintf(stderr, "%s: ", program_name);
		s = severity(prio);
		if (s)
			fprintf(stderr, "[%s] ", s);
		va_copy(tmp, ap);
		vfprintf(stderr, fmt, tmp);
		fputc('\n', stderr);
		va_end(tmp);
	}

	if (facility > 0) {
		if (syslog_include_prio && (s = severity(prio)) != NULL) {
			static char *fmtbuf;
			static size_t fmtsize;
			size_t len = strlen(fmt) + strlen(s) + 4;
			char *p;
			
			if (len > fmtsize) {
				fmtbuf = erealloc(fmtbuf, len);
				fmtsize = len;
			}

			p = fmtbuf;
			*p++ = '[';
			while (*s)
				*p++ = *s++;
			*p++ = ']';
			*p++ = ' ';
			while (*p++ = *fmt++);
			vsyslog(prio, fmtbuf, ap);
		} else			
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
		diag(LOG_CRIT, _("not enough memory"));
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
		diag(LOG_CRIT, _("not enough memory"));
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
trans_strtotok(struct transtab *tab, const char *str, int *ret)
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
	static int sigv[] = { SIGTERM, SIGQUIT, SIGINT, SIGHUP, SIGALRM,
			      SIGUSR1, SIGUSR1, SIGCHLD };
	sigv_set_all(sf, NITEMS(sigv), sigv, NULL);
}

void
storepid(const char *pidfile)
{
	FILE *fp = fopen(pidfile, "w");
	if (!fp) {
		diag(LOG_ERR, _("cannot open pidfile %s for writing: %s"),
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
		diag(LOG_ERR, 0, _("no user with UID %lu"),
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

void
ev_log(int flags, struct dirwatcher *dp)
{
	int i;
	char *p;
	
	if (debug_level > 0) {
		for (p = trans_tokfirst(sysev_transtab, flags, &i); p;
		     p = trans_toknext(sysev_transtab, flags, &i))
			debug(1, ("%s: %s", dp->dirname, p));
	}
}


/* Initialize generic event table */
void
genev_init()
{
	int i;
	
	for (i = 0; i < genev_xlat[i].gen_mask; i++)
		defevt(trans_toktostr(genev_transtab, genev_xlat[i].gen_mask),
		       &genev_xlat[i], 0);
}
	

int signo = 0;
int stop = 0;

pid_t self_test_pid;
int exit_code = 0;

void
sigmain(int sig)
{
	signo = sig;
	switch (signo) {
	case SIGCHLD:
	case SIGALRM:
		break;
	default:
		stop = 1;
	}
}

void
self_test()
{
	pid_t pid;
	char *args[4];
	
	pid = fork();
	if (pid == (pid_t)-1) {
		diag(LOG_CRIT,
		     _("cannot run `%s': fork failed: %s"),
		     self_test_prog, strerror(errno));
		exit(2);
	}
	
	if (pid != 0) {
		self_test_pid = pid;
		return;
	}

	args[0] = "/bin/sh";
	args[1] = "-c";
	args[2] = self_test_prog;
	args[3] = NULL;
	execv(args[0], args);

	diag(LOG_ERR, "execv: %s: %s", self_test_prog, strerror(errno));
	_exit(127);
}


#if USE_IFACE == IFACE_INOTIFY
# define INTERFACE "inotify"
#elif USE_IFACE == IFACE_KQUEUE
# define INTERFACE "kqueue"
#endif

static int opt_debug_level = 0;
static int opt_foreground = 0;
static char *opt_pidfile = NULL;
static char *opt_user = NULL;
static int opt_facility = -1;
static int lint_only = 0;

#include "cmdline.h"

int
main(int argc, char **argv)
{
	int i;

#ifdef ENABLE_NLS
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif

	set_program_name(argv[0]);
	tag = estrdup(program_name);

	genev_init();
	config_init();
	
	parse_options(argc, argv, &i);

	argc -= i;
	argv += i;

	switch (argc) {
	default:
		diag(LOG_CRIT, _("too many arguments"));
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
	if (opt_pidfile)
		pidfile = opt_pidfile;
	if (opt_facility != -1)
		facility = opt_facility;
	if (!foreground && facility <= 0)
		facility = LOG_DAEMON;
	if (opt_user)
		user = opt_user;
	
	if (facility > 0) {
		openlog(tag, LOG_PID, facility);
		grecs_log_to_stderr = 0;
	}

	if (foreground)
		setup_watchers();
	else {
		/* Become a daemon */
		if (detach(setup_watchers)) {
			diag(LOG_CRIT, "daemon: %s", strerror(errno));
			exit(1);
		}
		log_to_stderr = -1;
	}
	
	diag(LOG_INFO, _("%s %s started"), program_name, VERSION);

	/* Write pidfile */
	if (pidfile)
		storepid(pidfile);

	/* Relinquish superuser privileges */
	if (user && getuid() == 0)
		setuser(user);

	signal_setup(sigmain);

	if (self_test_prog)
		self_test();
	
	/* Main loop */
	while (!stop && sysev_select() == 0) {
		process_timeouts();
		process_cleanup(0);
	}

	diag(LOG_INFO, _("%s %s stopped"), program_name, VERSION);

	if (pidfile)
		unlink(pidfile);
	
	return exit_code;
}
