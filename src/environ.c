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
#include "wordsplit.h"
#include <ctype.h>

extern char **environ;    /* Environment */

#define DEBUG_ENVIRON(l,env) do {				\
	if (debug_level >= (l)) {				\
		diag(LOG_DEBUG, _("environment: "));		\
		for (i = 0; (env)[i]; i++)			\
			diag(LOG_DEBUG, "%s ", (env)[i]);	\
		diag(LOG_DEBUG, "\n");				\
	}							\
	} while (0)

static char *
find_env(const char *name, int val)
{
	if (environ) {
		int nlen = strcspn(name, "+=");
		int i;

		for (i = 0; environ[i]; i++) {
			size_t elen = strcspn(environ[i], "=");
			if (elen == nlen &&
			    memcmp(name, environ[i], nlen) == 0)
				return val ? environ[i] + elen + 1 : environ[i];
		}
	}
	return NULL;
}

static int
locate_unset(char **env, const char *name)
{
	int i;
	int nlen = strcspn(name, "=");

	for (i = 0; env[i]; i++) {
		if (env[i][0] == '-') {
			size_t elen = strcspn (env[i] + 1, "=");
			if (elen == nlen &&
			    memcmp (name, env[i] + 1, nlen) == 0) {
				if (env[i][nlen + 1])
					return strcmp(name + nlen,
						      env[i] + 1 + nlen) == 0;
				else
					return 1;
			}
		}
	}
	return 0;
}

static char *
env_concat(const char *name, size_t namelen, const char *a, const char *b)
{
	char *res;
	size_t len;
        
	if (a && b) {
		res = emalloc(namelen + 1 + strlen(a) + strlen(b) + 1);
		strcpy(res + namelen + 1, a);
		strcat(res, b);
	} else if (a) {
		len = strlen(a);
		if (ispunct(a[len-1]))
			len--;
		res = emalloc(namelen + 1 + len + 1);
		memcpy(res + namelen + 1, a, len);
		res[namelen + 1 + len] = 0;
	}
	else { /* if (a == NULL) */
		if (ispunct(b[0]))
			b++;
		len = strlen(b);
		res = emalloc(namelen + 1 + len + 1);
		strcpy(res + namelen + 1, b);
	}
	memcpy(res, name, namelen);
	res[namelen] = '=';
	return res;
}

static char *defenv[] = {
	"DIREVENT_SYSEV_CODE=${sysev_code}",
	"DIREVENT_SYSEV_NAME=${sysev_name}",
	"DIREVENT_GENEV_CODE=${genev_code}",
	"DIREVENT_GENEV_NAME=${genev_name}",
	"DIREVENT_FILE=${file}",
	NULL
};

char **
environ_setup(char **hint, char **kve)
{
	char *empty[1] = { NULL };
	char **old_env = environ;
	char **new_env;
	char **addenv = defenv;
	char *var;
	size_t count, i, n;
	struct wordsplit ws;
	int wsflags = WRDSF_NOCMD | WRDSF_QUOTE | WRDSF_NOSPLIT |
		      WRDSF_ENV | WRDSF_ENV_KV;

	ws.ws_env = (const char **) kve;

	if (!hint)
		hint = empty;
	else if (strcmp(hint[0], "-") == 0 || strcmp(hint[0], "--") == 0) {
		old_env = NULL;
		if (hint[0][1] == '-')
			addenv = empty;
		hint++;
        }
	
	/* Count new environment size */
	count = 0;
	if (old_env)
		for (i = 0; old_env[i]; i++)
			count++;

	for (i = 0; addenv[i]; i++)
		count++;
	
	for (i = 0; hint[i]; i++)
		count++;

	if (self_test_pid)
		count++;

	/* Allocate new environment. */
	new_env = ecalloc(count + 1, sizeof new_env[0]);
  
	/* Populate the environment. */
	n = 0;
  
	if (old_env)
		for (i = 0; old_env[i]; i++) {
			if (!locate_unset(hint, old_env[i]))
				new_env[n++] = old_env[i];
		}

	for (i = 0; addenv[i]; i++)
		if (!locate_unset(hint, addenv[i])) {
			if (wordsplit(addenv[i], &ws, wsflags)) {
				diag(LOG_CRIT, "wordsplit: %s",
				     wordsplit_strerror(&ws));
				_exit(127);
			}
			wsflags |= WRDSF_REUSE;
			new_env[n++] = estrdup(ws.ws_wordv[0]);
		}
		
	for (i = 0; hint[i]; i++) {
		char *p;

		if (hint[i][0] == '-') {
			/* Skip unset directives. */
			continue;
		}

		if (wordsplit(hint[i], &ws, wsflags)) {
			diag(LOG_CRIT, "wordsplit: %s",
			     wordsplit_strerror(&ws));
			_exit(127);
		}
		wsflags |= WRDSF_REUSE;
		var = ws.ws_wordv[0];
		
		if ((p = strchr(var, '='))) {
			if (p == var)
				continue; /* Ignore erroneous entry */
			if (p[-1] == '+') 
				new_env[n++] = env_concat(var,
							  p - var - 1,
							  find_env(var, 1),
							  p + 1);
			else if (p[1] == '+')
				new_env[n++] = env_concat(var,
							  p - var,
							  p + 2,
							  find_env(var, 1));
			else
				new_env[n++] = estrdup(var);
		} else {
			p = find_env(var, 0);
			if (p)
				new_env[n++] = p;
		}
	}
	if (self_test_pid) {
		char buf[512];
		snprintf(buf, sizeof buf, "DIREVENT_SELF_TEST_PID=%lu",
			 (unsigned long)self_test_pid);
		new_env[n++] = estrdup(buf);;
	}
	new_env[n] = NULL;

	if (wsflags & WRDSF_REUSE)
		wordsplit_free(&ws);
	return new_env;
}
