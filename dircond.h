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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>

#ifndef DEFAULT_TIMEOUT
# define DEFAULT_TIMEOUT 5
#endif

/* Handler flags. */
#define HF_NOWAIT 0x01       /* Don't wait for termination */
#define HF_STDOUT 0x02       /* Capture stdout */
#define HF_STDERR 0x04       /* Capture stderr */

/* Event description */
struct event {
	int evcode;
	char *evname;
};

/* Handler structure */
struct handler {
	struct handler *next;
	int ev_mask;         /* Event mask */
	int flags;           /* Handler flags */
	const char *prog;    /* Handler program (no arguments allowed) */
	uid_t uid;           /* Run as this user (unless 0) */
	gid_t *gidv;          /* Run with these groups' privileges */
	size_t gidc;         /* Number of elements in gidv */
	unsigned timeout;    /* Handler timeout */
};

/* A directory watcher is described by the following structure */
struct dirwatcher {
	int refcnt;
	int wd;                              /* Watch descriptor */
	struct dirwatcher *parent;           /* Points to the parent watcher.
					        NULL for top-level watchers */
	char *dirname;                       /* Pathname being watched */
	struct handler *handler_list;        /* Handlers */
	int depth;
};

extern int foreground;
extern int debug_level;
extern int facility;
extern char *tag;
extern char *pidfile;
extern char *user;
extern unsigned opt_timeout;
extern unsigned opt_flags;
extern int opt_facility;
extern int signo;

void *emalloc(size_t size);
void *ecalloc(size_t nmemb, size_t size);
void *erealloc(void *ptr, size_t size);
char *estrdup(const char *str);

char *mkfilename(const char *dir, const char *file);

void diag(int prio, const char *fmt, ...);
void debugprt(const char *fmt, ...);

#define debug(l, c) do { if (debug_level>=(l)) debugprt c; } while(0)

extern int evsys_filemask;
void evsys_init(void);
int evsys_add_watch(struct dirwatcher *dwp, int mask);
void evsys_rm_watch(struct dirwatcher *dwp);
void evsys_loop(void);
int evsys_name_to_code(const char *name);
const char *evsys_code_to_name(int code);

int defevt(const char *name, int mask, int line);
int getevt(const char *name);


struct hashtab;
struct hashent {
	int used;
};
int hashtab_replace(struct hashtab *st, void *ent, void **old_ent);
const char *hashtab_strerror(int rc);
int hashtab_remove(struct hashtab *st, void *elt);
int hashtab_get_index(unsigned *idx, struct hashtab *st, void *key,
		      int *install);
void *hashtab_lookup_or_install(struct hashtab *st, void *key, int *install);
void hashtab_clear(struct hashtab *st);
struct hashtab *hashtab_create(size_t elsize, 
			       unsigned (*hash_fun)(void *, unsigned long),
			       int (*cmp_fun)(const void *, const void *),
			       int (*copy_fun)(void *, void *),
			       void *(*alloc_fun)(size_t),
			       void (*free_fun)(void *));
void hashtab_free(struct hashtab *st);
size_t hashtab_count_entries(struct hashtab *st);

typedef int (*hashtab_enumerator_t) (struct hashent *, void *);
int hashtab_foreach(struct hashtab *st, hashtab_enumerator_t fun,
		    void *data);
size_t hashtab_count(struct hashtab *st);

unsigned hash_string(const char *name, unsigned long hashsize);

struct pathent {
	struct pathent *next;
	long depth;
	size_t len;
	char path[1];
};
	
struct pathdefn {
	int used;
	char *name;
	struct pathent *pathlist;
};

int pathdefn_add(const char *name, const char *dir, long depth);
struct pathent *pathdefn_get(const char *name);

void config_parse(const char *file);
int read_facility(const char *arg, int *pres);

void setup_watchers(void);
struct dirwatcher *dirwatcher_lookup_wd(int wd);
int check_new_watcher(const char *dir, const char *name);
struct dirwatcher *dirwatcher_install(const char *path, int *pnew);
void remove_watcher(const char *dir, const char *name);

int run_handler(struct dirwatcher *dp, struct handler *hp, int event,
		const char *file);
