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

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include "dircond.h"


/* Event codes */
struct event {
	int evcode;
	char *evname;
};

struct event events[] = {
	{ IN_ACCESS,        "access" },
	{ IN_ATTRIB,        "attrib" },       
	{ IN_CLOSE_WRITE,   "close_write" },  
	{ IN_CLOSE_NOWRITE, "close_nowrite" },
	{ IN_CREATE,        "create" },       
	{ IN_DELETE,        "delete" },      
	{ IN_MODIFY,        "modify" },
	{ IN_MOVED_FROM,    "moved_from" },    
	{ IN_MOVED_TO,      "moved_to" },      
	{ IN_OPEN,          "open" },
	{ 0 }
};

void
ev_log(struct inotify_event *ep, struct dirwatcher *dp)
{
	int i;

	if (debug_level > 0) {
		for (i = 0; events[i].evname; i++) {
			if (events[i].evcode & ep->mask)
				debug(1, ("%s/%s: %s", dp->dirname, ep->name,
					  events[i].evname));
		}
	}
}

/* Convert event name to event code */
int
ev_name_to_code(const char *name)
{
	int i;

	for (i = 0; events[i].evname; i++) {
		if (strcmp(events[i].evname, name) == 0)
			return events[i].evcode;
	}
	return 0;
}

const char *
ev_code_to_name(int code)
{
	int i;

	for (i = 0; events[i].evname; i++) {
		if (events[i].evcode & code)
			return events[i].evname;
	}
	return NULL;
}


struct symevt {
	int used;
	char *name;
	int mask;
	int line;
};

struct hashtab *evtab;

static unsigned
symevt_hash(void *data, unsigned long hashsize)
{
	struct symevt *sym = data;
	return hash_string(sym->name, hashsize);
}

static int
symevt_cmp(const void *a, const void *b)
{
	struct symevt const *syma = a;
	struct symevt const *symb = b;

	return strcmp(syma->name, symb->name);
}

static int
symevt_copy(void *a, void *b)
{
	struct symevt *syma = a;
	struct symevt *symb = b;

	syma->used = 1;
	syma->name = estrdup(symb->name);
	return 0;
}

static void
symevt_free(void *p)
{
	struct symevt *sym = p;
	free(sym->name);
	free(sym);
}


int
defevt(const char *name, int mask, int line)
{
	struct symevt key, *evp;
	int install = 1;
	
	if (!evtab) {
		evtab = hashtab_create(sizeof(struct symevt),
				       symevt_hash, symevt_cmp,
				       symevt_copy,
				       NULL, symevt_free);
		if (!evtab) {
			diag(LOG_CRIT, "not enough memory");
			exit(1);
		}
	}

	key.name = (char *) name;
	evp = hashtab_lookup_or_install(evtab, &key, &install);
	if (!install)
		return evp->line;
	evp->mask = mask;
	evp->line = line;
	return 0;
}

int
getevt(const char *name)
{
	if (evtab) {
		struct symevt key, *evp;
		key.name = (char *) name;
		evp = hashtab_lookup_or_install(evtab, &key, NULL);
		if (evp)
			return evp->mask;
	}
	return ev_name_to_code(name);
}
