/* direvent - directory content watcher daemon
   Copyright (C) 2012-2014 Sergey Poznyakoff

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

#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <regex.h>

#include "gettext.h"

#define _(s) gettext(s)
#define N_(s) s

/* Generic (system-independent) event codes */
#define GENEV_CREATE  0x01
#define GENEV_WRITE   0x02
#define GENEV_ATTRIB  0x04
#define GENEV_DELETE  0x08

/* Handler flags. */
#define HF_NOWAIT 0x01       /* Don't wait for termination */
#define HF_STDOUT 0x02       /* Capture stdout */
#define HF_STDERR 0x04       /* Capture stderr */

#ifndef DEFAULT_TIMEOUT
# define DEFAULT_TIMEOUT 5
#endif

typedef struct {
	int gen_mask;        /* Generic event mask */
	int sys_mask;        /* System event mask */
} event_mask;

/* Event description */
struct transtab {
	char *name;
	int tok;
};

#define PAT_GLOB  0
#define PAT_REGEX 1

struct filename_pattern {
	int type;
	int neg;
	union {
		regex_t re;
		char *glob;
	} v;
};

/* Handler structure */
struct handler {
	struct handler *next;
	event_mask ev_mask;  /* Event mask */
	struct grecs_list *fnames;  /* File name patterns */
	int flags;           /* Handler flags */
	const char *prog;    /* Handler program (with eventual arguments) */
	uid_t uid;           /* Run as this user (unless 0) */
	gid_t *gidv;         /* Run with these groups' privileges */
	size_t gidc;         /* Number of elements in gidv */
	unsigned timeout;    /* Handler timeout */
	char **env;          /* Environment */
};

/* A directory watcher is described by the following structure */
struct dirwatcher {
	int refcnt;
	int wd;                              /* Watch descriptor */
	struct dirwatcher *parent;           /* Points to the parent watcher.
					        NULL for top-level watchers */
	char *dirname;                       /* Pathname being watched */
	struct handler *handler_list;        /* List of handlers */
	struct handler *handler_tail;        /* Tail of the handler list */
	int depth;                           /* Recursion depth */
	char *split_p;                       /* Points to the deleted directory
						separator in dirname (see
						split_pathname,
						unsplit_pathname */
#if USE_IFACE == IFACE_KQUEUE
	mode_t file_mode;
	time_t file_ctime;
#endif
};

#define __cat2__(a,b) a ## b
#define handler_matches_event(h,m,f,n)		\
	(((h)->ev_mask.__cat2__(m,_mask) & (f)) && \
	 filename_pattern_match((h)->fnames, n) == 0)


extern int foreground;
extern int debug_level;
extern int facility;
extern char *tag;
extern int syslog_include_prio;
extern char *pidfile;
extern char *user;
extern unsigned opt_timeout;
extern unsigned opt_flags;
extern int signo;
extern int stop;

extern pid_t self_test_pid;
extern int exit_code;


void *emalloc(size_t size);
void *ecalloc(size_t nmemb, size_t size);
void *erealloc(void *ptr, size_t size);
char *estrdup(const char *str);

char *mkfilename(const char *dir, const char *file);

void diag(int prio, const char *fmt, ...);
void debugprt(const char *fmt, ...);

#define debug(l, c) do { if (debug_level>=(l)) debugprt c; } while(0)

void signal_setup(void (*sf) (int));
int detach(void (*)(void));

int sysev_filemask(struct dirwatcher *dp);
void sysev_init(void);
int sysev_add_watch(struct dirwatcher *dwp, event_mask mask);
void sysev_rm_watch(struct dirwatcher *dwp);
int sysev_select(void);
int sysev_name_to_code(const char *name);
const char *sysev_code_to_name(int code);

int defevt(const char *name, event_mask *mask, int line);
int getevt(const char *name, event_mask *mask);
int evtnullp(event_mask *mask);
event_mask *event_mask_init(event_mask *m, int fflags, event_mask const *);
void evtsetall(event_mask *m);

/* Translate generic events to system ones and vice-versa */
extern event_mask genev_xlat[];
/* Translate generic event codes to symbolic names and vice-versa */
extern struct transtab genev_transtab[];
/* Translate system event codes to symbolic names and vice-versa */
extern struct transtab sysev_transtab[];

int trans_strtotok(struct transtab *tab, const char *str, int *ret);
char *trans_toktostr(struct transtab *tab, int tok);
char *trans_tokfirst(struct transtab *tab, int tok, int *next);
char *trans_toknext(struct transtab *tab, int tok, int *next);


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
	long depth;
	size_t len;
	char path[1];
};

void config_help(void);
struct grecs_node;
void config_finish(struct grecs_node *tree);
void config_parse(const char *file);

int get_facility(const char *arg);
int get_priority(const char *arg);

void setup_watchers(void);
struct dirwatcher *dirwatcher_lookup(const char *dirname);
struct dirwatcher *dirwatcher_lookup_wd(int wd);
int check_new_watcher(const char *dir, const char *name);
struct dirwatcher *dirwatcher_install(const char *path, int *pnew);
void dirwatcher_destroy(struct dirwatcher *dwp);
int watch_pathname(struct dirwatcher *parent, const char *dirname, int isdir, int notify);

char *split_pathname(struct dirwatcher *dp, char **dirname);
void unsplit_pathname(struct dirwatcher *dp);

void ev_log(int flags, struct dirwatcher *dp);
void deliver_ev_create(struct dirwatcher *dp, const char *name);
int subwatcher_create(struct dirwatcher *parent, const char *dirname,
		      int isdir, int notify);

struct process *process_lookup(pid_t pid);
void process_cleanup(int expect_term);
void process_timeouts(void);
int run_handler(struct handler *hp, event_mask *event,
		const char *dir, const char *file);
char **environ_setup(char **hint, char **kve);

#define NITEMS(a) ((sizeof(a)/sizeof((a)[0])))
struct sigtab {
	int signo;
	void (*sigfun)(int);
};

int sigv_set_action(int sigc, int *sigv, struct sigaction *sa);
int sigv_set_all(void (*handler)(int), int sigc, int *sigv,
		 struct sigaction *retsa);
int sigv_set_tab(int sigc, struct sigtab *sigtab, struct sigaction *retsa);
int sigv_set_action_tab(int sigc, struct sigtab *sigtab, struct sigaction *sa);

void filename_pattern_free(void *p);
int filename_pattern_match(struct grecs_list *lp, const char *name);

