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
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include "dircond.h"

unsigned opt_timeout;
unsigned opt_flags;

static const char *filename;
static int line;
static FILE *fp;
static char *buffer;
static size_t bufsize;
static char *curp;
static char *tknp;
static int errors;

static char *
skipws()
{
	while (*curp == ' ' || *curp == '\t') curp++;
	return curp;
}

static char *
skipword()
{
	while (*curp && !(*curp == ' ' || *curp == '\t')) curp++;
	return curp;
}

int
nextln()
{
	int off = 0;

	if (!buffer) {
		bufsize = 10;
		buffer = emalloc(bufsize);
	}

	for (;;) {
		char *p;
		
		while (p = fgets(buffer + off, bufsize - off, fp)) {
			int len = strlen(buffer+off);
			off += len;
			if (buffer[off-1] == '\n') {
				buffer[--off] = 0;
				line++;
				break;
			}
			bufsize *= 2;
			buffer = erealloc(buffer, bufsize);
		}

		if (!p && off == 0)
			return -1;
		
		if (buffer[off-1] == '\\')
			buffer[--off] = 0;
		else
			break;
	}
	curp = buffer;
	return off;
}

int
nextneln()
{
	int rc;
	
	do {
		if ((rc = nextln()) < 0)
			break;
		skipws();
	} while (*curp == 0 || *curp == '#');
	return rc;
}

static char *
nextkn()
{
	tknp = curp;
	if (*tknp) {
		skipword();
		if (*curp)
			*curp++ = 0;
		if (*tknp == '#')
			*tknp = 0;
	}
	return tknp;
}

static char *
nextnetkn()
{
	if (!*nextkn()) {
		diag(LOG_ERR, "%s:%d: unexpected end of line", filename, line);
		return NULL;
	}
	return tknp;
}

static int
parse_foreground()
{
	if (*nextkn() != 0) {
		if (strcmp(tknp, "on") == 0)
			foreground = 1;
		else if (strcmp(tknp, "off") == 0)
			foreground = 0;
		else {
			diag(LOG_ERR,
			     "%s:%d: expected \"on\" or \"of\", "
			     "but found \"%s\"",
			     filename, line, tknp);
			return 1;
		}
	} else
		foreground = 1;
	return 0;
}

static int
parse_debug()
{
	char *p;

	if (!nextnetkn())
		return 1;
		
	debug_level = strtoul(tknp, &p, 10);
	if (*p) {
		diag(LOG_ERR, "%s:%d: invalid debug level",
		     filename, line);
		return 1;
	}
	return 0;
}

static int
parse_pidfile()
{
	if (!nextnetkn())
		return 1;
	pidfile = estrdup(tknp);
	return 0;
}

static int
parse_user()
{
	if (!nextnetkn())
		return 1;
	if (!getpwnam(tknp)) {
		diag(LOG_ERR, "%s:%d: no such user: %s", filename, line, user);
		return 1;
	}
			
	user = estrdup(tknp);
	return 0;
}

int
read_facility(const char *arg, int *pres)
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
		errno = EINVAL;
		return -1;
	}
	if (n > 256) {
		errno = ERANGE;
		return -1;
	}
	*pres = n;
	return 0;
}

static int
parse_syslog()
{
	char *kw;
	
	if (!nextnetkn())
		return 1;
	kw = tknp;
	if (strcmp(kw, "off") == 0) {
		facility = -1;
		return 0;
	}
	
	if (!nextnetkn())
		return 1;
	if (strcmp(kw, "tag") == 0) 
		tag = estrdup(tknp);
	else if (strcmp(kw, "facility") == 0) {
		if (read_facility(tknp, &facility)) {
			switch (errno) {
			case EINVAL:
				diag(LOG_ERR,
				     "%s:%d: unknown syslog facility: %s",
				     filename, line, tknp);
				break;

			case ERANGE:
				diag(LOG_ERR,
				     "%s:%d: syslog facility out of range",
				     filename, line);
				break;
				
			default:
				abort();
			}
			return 1;
		}
	} else {
		diag(LOG_ERR, "%s:%d: unrecognized keyword: %s",
		     filename, line, tknp);
	}
	return 0;
}

static int
parse_option()
{
	char *optname, *arg;
	
	if (!nextnetkn())
		return 1;
	optname = tknp;

	if (strcmp(optname, "nowait") == 0) {
		opt_flags &= ~HF_NOWAIT;
		return 0;
	} else if (strcmp(optname, "wait") == 0) {
		opt_flags |= HF_NOWAIT;
		return 0;
	}
	
	if (!nextnetkn())
		return 1;
	arg = tknp;
	
	if (strcmp(optname, "timeout") == 0) {
		char *p;
		
		opt_timeout = strtoul(arg, &p, 10);
		if (*p) {
			diag(LOG_ERR, "%s:%d: invalid timeout",
			     filename, line);
			return 1;
		}
		return 0;
	} else if (strcmp(optname, "capture") == 0) {
		int flag;
		
		if (strcmp(arg, "stdout") == 0)
			flag = HF_STDOUT;
		else if (strcmp(arg, "stderr") == 0)
			flag = HF_STDERR;
		else if (strcmp(arg, "both") == 0)
			flag = HF_STDOUT|HF_STDERR;
		else {
			diag(LOG_ERR,
			     "%s:%d: expected \"stdout\", \"stderr\", "
			     "or \"both\", "
			     "but found \"%s\"",
			     filename, line, arg);
		}

		if (*nextkn() != 0) {
			if (strcmp(tknp, "on") == 0)
				opt_flags |= flag;
			else if (strcmp(tknp, "off") == 0)
				opt_flags &= ~flag;
			else {
				diag(LOG_ERR,
				     "%s:%d: expected \"on\" or \"of\", "
				     "but found \"%s\"",
				     filename, line, tknp);
				return 1;
			}
		} else
			opt_flags |= flag;
		
		return 0;
	}

	diag(LOG_ERR, "%s:%d: unknown option", filename, line);
	return 1;
}

static int
parse_path()
{
	const char *id, *path;
	long depth = 0;
	
	if (!nextnetkn())
		return 1;
	id = tknp;

	if (!nextnetkn())
		return 1;
	path = tknp;
	
	if (*nextkn()) {
		if (strcmp(tknp, "recursive") == 0) {
			if (*nextkn()) {
				char *p;

				depth = strtol(tknp, &p, 10);
				if (*p) {
					diag(LOG_ERR, "%s:%d: invalid depth",
					     filename, line);
					return 1;
				}
			} else
				depth = -1;
		}
	}
		
	pathdefn_add(id, path, depth);

	return 0;
}

static int
parse_event()
{
	const char *evname;
	int mask = 0, n;
	
	if (!nextnetkn())
		return 1;
	evname = tknp;

	while (*nextkn()) {
		n = getevt(tknp);
		if (n == 0) {
			diag(LOG_ERR, "%s:%d: unrecognized event code: %s",
			     filename, line, n);
			errors++;
			continue;
		}
		mask |= n;
	}

	if (mask == 0) {
		diag(LOG_ERR, "%s:%d: empty event set", filename, line);
		errors++;
		return 0;
	}

	n = defevt(evname, mask, line);
	if (n) {
		diag(LOG_ERR, "%s:%d: event redefined", filename, line);
		diag(LOG_ERR,
		     "%s:%d: this is the location of the prior definition",
		     filename, n);
		errors++;
		return 0;
	}
	
	return 0;
}

/* on EVTID PATHID call PROGRAM */
static int
parse_onevent()
{
	int mask;
	struct pathent *pathent;
	struct handler *hp, *prev = NULL;
	
	if (!nextnetkn())
		return 1;
	mask = getevt(tknp);
	if (mask == 0) {
		diag(LOG_ERR, "%s:%d: unknown event code: %s",
		     filename, line, tknp);
		return 1;
	}

	if (!nextnetkn())
		return 1;
	if (strcmp(tknp, "in")) {
		diag(LOG_ERR, "%s:%d: expected \"in\", but found \"%s\"",
		     filename, line, tknp);
		return 1;
	}

	if (!nextnetkn())
		return 1;
	
	pathent = pathdefn_get(tknp);
	if (!pathent) {
		diag(LOG_ERR, "%s:%d: unknown pathset name: %s",
		     filename, line, tknp);
		return 1;
	}

	if (!nextnetkn())
		return 1;
	if (strcmp(tknp, "call")) {
		diag(LOG_ERR, "%s:%d: expected \"call\", but found \"%s\"",
		     filename, line, tknp);
		return 1;
	}
	if (!nextnetkn())
		return 1;

	for (; pathent; pathent = pathent->next) {
		struct dirwatcher *dwp = dirwatcher_install(pathent->path,
							    NULL);
		
		if (!dwp)
			abort();
		dwp->depth = pathent->depth;

		for (hp = dwp->handler_list; hp; prev = hp, hp = hp->next) {
			if (strcmp(dwp->dirname, pathent->path) == 0) {
				diag(LOG_ERR,
				     "%s:%d: ignoring duplicate definition",
				     filename, line);
				//FIXME: check mask?
				return 0;
			}
		}

		hp = emalloc(sizeof(*hp));
		hp->ev_mask = mask;
		hp->flags = opt_flags;
		hp->timeout = opt_timeout;
		hp->prog = estrdup(tknp);
		
		if (prev)
			prev->next = hp;
		else
			dwp->handler_list = hp;
	}
	return 0;
}

struct stmt_handler {
	const char *tok;
	int (*parser)();
};

struct stmt_handler stmtab[] = {
	{ "foreground", parse_foreground },
	{ "debug", parse_debug },
	{ "pidfile", parse_pidfile },
	{ "syslog", parse_syslog },
	{ "user", parse_user },
	{ "option", parse_option },
	{ "event", parse_event },
	{ "path", parse_path },
	{ "onevent", parse_onevent },
	{ NULL }
};

struct stmt_handler *
find_stmt(const char *s)
{
	struct stmt_handler *p;

	for (p = stmtab; p->tok; p++)
		if (strcmp(p->tok, s) == 0)
			return p;
	return NULL;
}

void
config_parse(const char *file)
{
	filename = file;
	line = 0;
	errors = 0;
	fp = fopen(file, "r");
	if (!fp) {
		diag(LOG_CRIT, "cannot open file %s for reading: %s",
		     file, strerror(errno));
		exit(1);
	}

	while (nextneln() >= 0) {
		struct stmt_handler *hp = find_stmt(nextkn());
		
		if (hp) {
			if (hp->parser()) {
				tknp = NULL;
				errors++;
			} else if (*nextkn()) {
				diag(LOG_ERR,
				     "%s:%d: garbage at the end of line",
				     filename, line);
				tknp = NULL;
				errors++;
			}
		} else {
			diag(LOG_ERR, "%s:%d: unrecognized statement",
			     filename, line);
			tknp = NULL;
			errors++;
		}
	}
	
	fclose(fp);

	if (errors)
		exit(1);
}
