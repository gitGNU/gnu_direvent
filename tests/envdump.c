/* envdump.c - dump execution environment
   This file is part of Direvent testsuite.
   Copyright (C) 2013-2016 Sergey Poznyakoff

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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

extern char **environ;
char *progname;

char *
agetcwd()
{
	char *buf = NULL;
	size_t bufsize = 128;
	
	for (;;) {
		errno = 0;
		buf = malloc(bufsize);
		if (!buf) {
			fprintf(stderr, "%s: not enough memory\n", progname);
			return NULL;
		}
		if (getcwd(buf, bufsize))
			break;
		free(buf);
		if (errno != ERANGE) {
			fprintf(stderr, "%s: ", progname);
			perror("getcwd");
			return NULL;
		}

		bufsize += bufsize / 16;
		bufsize += 32;
	}
	return buf;
}

int
compvar(char *enva, char *envb, int lazy)
{
	int c;

	for (; *envb; enva++, envb++) {
		if (*enva == 0) {
			if (lazy)
				return 0;
			break;
		}
		if (c = *enva - *envb)
			return c;
		if (*enva == '=' || *envb == '=')
			return c;
	}
	
	return *enva - *envb;
}

int
compenv(const void *a, const void *b)
{
	return compvar(*(char * const *)a, *(char * const *)b, 0);
}

char *
locate(char **itab, char *s)
{
	for (;*itab;itab++) {
		if (compvar(*itab, s, 1) == 0)
			break;
	}
	return *itab;
}

struct sigtab {
	char *name;
	int sig;
} sigtab[] = {
	{ "HUP", SIGHUP },
	{ "INT", SIGINT },
	{ "QUIT", SIGQUIT },
	{ "ILL", SIGILL },
	{ "ABRT", SIGABRT },
	{ "FPE", SIGFPE },
	{ "KILL", SIGKILL },
	{ "SEGV", SIGSEGV },
	{ "PIPE", SIGPIPE },
	{ "ALRM", SIGALRM },
	{ "TERM", SIGTERM },
	{ "USR1", SIGUSR1 },
	{ "USR2", SIGUSR2 },
	{ "CHLD", SIGCHLD },
	{ NULL }
};

int
strtosig(char *str)
{
	struct sigtab *sp;
	int sig;
	char *end;
		
	if (strncmp(str, "SIG", 3) == 0)
		str += 3;
	for (sp = sigtab; sp->name; sp++)
		if (strcmp(sp->name, str) == 0)
			return sp->sig;

	sig = strtoul(str, &end, 10);
	if (*end) {
		fprintf(stderr, "%s: bad signal number (near %s)\n",
			progname, end);
		exit(1);
	}
	return sig;
}

void
read_pid_and_sig(char *arg, pid_t *pid, int *sig)
{
	char *p, *end;
	unsigned long n;

	p = strchr(arg, ':');
	if (p)
		*p++ = 0;

	if (arg[0] == '@') {
		FILE *fp = fopen(++arg, "r");
		if (!fp) {
			fprintf(stderr, "%s: cannot open ", progname);
			perror(arg);
			exit(1);
		}
		if (fscanf(fp, "%lu", &n) != 1) {
			fprintf(stderr, "%s: no PID found in %s\n", progname,
				arg);
			exit(1);
		}
		fclose(fp);
		*pid = n;
	} else {
		*pid = strtoul(arg, &end, 10);
		if (*end) {
			fprintf(stderr,
				"%s: bad PID (near %s)\n", progname, end);
			exit(1);
		}
	}

	if (p) {
		*sig = strtosig(p);
		p[-1] = ':';
	}
}

int
main(int argc, char **argv)
{
	int i;
	char *p;
	FILE *fp = NULL;
	char *file;
	char *mode = "w";
	int sortenv = 0;
	char *include = NULL;
	char **itab = NULL;
	pid_t pid = 0;
	int sig = SIGHUP;
	
	progname = strrchr(argv[0], '/');
	if (progname)
		progname++;
	else
		progname = argv[0];
	while ((i = getopt(argc, argv, "af:hi:k:s")) != EOF)
		switch (i) {
		case 'a':
			mode = "a";
			break;
		case 'f':
			file = optarg;
			break;
		case 'h':
			printf("usage: %s [-ahsx] [-f FILE] [-i INCLUDELIST] [-k [@]PID[:SIG]] [ARGS...]\n",
			       progname);
			return 0;
		case 's':
			sortenv = 1;
			break;
		case 'i':
			include = optarg;
			break;
		case 'k':
			read_pid_and_sig(optarg, &pid, &sig);
			break;
		default:
			return 1;
		}

	if (file) {
		fp = fopen(file, mode);
		if (!fp) {
			fprintf(stderr, "%s: ", progname);
			perror(file);
			return 1;
		}
	} else
		fp = stderr;
	
	fprintf(fp, "# Dump of execution environment\n");
	p = agetcwd();
	if (p) {
		fprintf(fp, "cwd is %s\n", p);
		free(p);
	}
	fprintf(fp, "# Arguments\n");
	for (i = 0; i < argc; i++)
		fprintf(fp, "argv[%d]=%s\n", i, argv[i]);

	if (sortenv) {
		for (i = 0; environ[i]; i++);
		qsort(environ, i, sizeof(environ[0]), compenv);
	}
	if (include) {
		i = 1;
		for (p = include; *p; p++) {
			if (*p == ':')
				i++;
		}
		itab = calloc(i + 1, sizeof(itab));

		itab[0] = include;
		for (p = include, i = 1; *p; p++) {
			if (*p == ':') {
				*p = 0;
				itab[i++] = p + 1;
			}
		}
		itab[i] = NULL;
	}
		
	fprintf(fp, "# Environment\n");
	for (i = 0; environ[i]; i++) {
		if (!itab || locate(itab, environ[i]))
			fprintf(fp, "%s\n", environ[i]);
	}
	fprintf(fp, "# End\n");

	if (pid)
		kill(pid, sig);

	return 0;
}
	
