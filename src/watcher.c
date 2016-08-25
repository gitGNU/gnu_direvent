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
#include <dirent.h>
#include <sys/stat.h>

void
watchpoint_ref(struct watchpoint *wpt)
{
	++wpt->refcnt;
}

void
watchpoint_unref(struct watchpoint *wpt)
{
	if (--wpt->refcnt)
		return;
	free(wpt->dirname);
	handler_list_unref(wpt->handler_list);
	free(wpt);
}


struct wpref {
	int used;
	struct watchpoint *wpt;
};

static unsigned
wpref_hash(void *data, unsigned long hashsize)
{
	struct wpref *sym = data;
	return grecs_hash_string(sym->wpt->dirname, hashsize);
}

static int
wpref_cmp(const void *a, const void *b)
{
	struct wpref const *syma = a;
	struct wpref const *symb = b;

	return strcmp(syma->wpt->dirname, symb->wpt->dirname);
}

static int
wpref_copy(void *a, void *b)
{
	struct wpref *syma = a;
	struct wpref *symb = b;

	syma->used = 1;
	syma->wpt = symb->wpt;
	return 0;
}

static void
wpref_free(void *p)
{
	struct wpref *wpref = p;
	watchpoint_unref(wpref->wpt);
	free(wpref);
}

struct grecs_symtab *nametab;

struct watchpoint *
watchpoint_install(const char *path, int *pnew)
{
	struct watchpoint wpkey;
	struct wpref key;
	struct wpref *ent;
	int install = 1;

	if (!nametab) {
		nametab = grecs_symtab_create(sizeof(struct wpref),
					      wpref_hash, wpref_cmp, wpref_copy,
					      NULL, wpref_free);
		if (!nametab) {
			diag(LOG_CRIT, _("not enough memory"));
			exit(1);
		}
	}

	wpkey.dirname = (char*) path;
	key.wpt = &wpkey;
	ent = grecs_symtab_lookup_or_install(nametab, &key, &install);
	if (install) {
	        struct watchpoint *wpt = ecalloc(1, sizeof(*wpt));
		wpt->dirname = estrdup(path);
		wpt->wd = -1;
		wpt->handler_list = handler_list_create();
		wpt->refcnt = 0;
		ent->wpt = wpt;
	}
	if (!ent)
		abort(); /* FIXME */
	watchpoint_ref(ent->wpt);
	if (pnew)
		*pnew = install;
	return ent->wpt;
}

struct watchpoint *
watchpoint_install_ptr(struct watchpoint *wpt)
{
	struct wpref key;
	int install = 1;
	key.wpt = wpt;
	
	if (!grecs_symtab_lookup_or_install(nametab, &key, &install)) {
		diag(LOG_CRIT, _("not enough memory"));
		exit(1);
	}
	watchpoint_ref(wpt);
	return wpt;
}	
	
static void
wpref_destroy(void *data)
{
	struct watchpoint *wpt = data;
	watchpoint_destroy(wpt);
}

static grecs_list_ptr_t watchpoint_gc_list;

void
watchpoint_gc(void)
{
	if (watchpoint_gc_list) {
		grecs_list_free(watchpoint_gc_list);
		watchpoint_gc_list = NULL;
	}
}

struct watchpoint *
watchpoint_lookup(const char *dirname)
{
	struct watchpoint wpkey;
	struct wpref key;
	struct wpref *ent;

	if (!nametab)
		return NULL;
	
	wpkey.dirname = (char*) dirname;
	key.wpt = &wpkey;
	ent = grecs_symtab_lookup_or_install(nametab, &key, NULL);
	return ent ? ent->wpt : NULL;
}

static void
watchpoint_remove(const char *dirname)
{
	struct watchpoint wpkey;
	struct wpref key;

	if (!nametab)
		return;
	
	wpkey.dirname = (char*) dirname;
	key.wpt = &wpkey;
	grecs_symtab_remove(nametab, &key);
}

void
watchpoint_destroy(struct watchpoint *wpt)
{
	debug(1, (_("removing watcher %s"), wpt->dirname));
	sysev_rm_watch(wpt);
	watchpoint_remove(wpt->dirname);
}

void
watchpoint_suspend(struct watchpoint *wpt)
{
	if (!wpt->parent) /* A top-level watchpoint */
		watchpoint_install_sentinel(wpt);//FIXME: error checking
	watchpoint_destroy(wpt);
	if (grecs_symtab_count(nametab) == 0) {
		diag(LOG_CRIT, _("no watchers left; exiting now"));
		stop = 1;
	}
}

struct sentinel {
	struct handler *hp;
	struct watchpoint *watchpoint;
};

static int
sentinel_handler_run(struct watchpoint *wp, event_mask *event,
		     const char *dirname, const char *file, void *data)
{
	struct sentinel *sentinel = data;
	struct watchpoint *wpt = sentinel->watchpoint;
	
	watchpoint_init(wpt);
	watchpoint_install_ptr(wpt);
	deliver_ev_create(wpt, dirname, file);
	
	if (handler_list_remove(wp->handler_list, sentinel->hp) == 0) {
		if (!watchpoint_gc_list) {
			watchpoint_gc_list = grecs_list_create();
			watchpoint_gc_list->free_entry = wpref_destroy;
		}
		grecs_list_append(watchpoint_gc_list, wp);
	}
	return 0;
}

static void
sentinel_handler_free(void *ptr)
{
	struct sentinel *sentinel = ptr;
	watchpoint_unref(sentinel->watchpoint);
	free(sentinel);
}

int
watchpoint_install_sentinel(struct watchpoint *wpt)
{
	struct watchpoint *sent;
	char *dirname;
	char *filename;
	struct handler *hp;
	event_mask ev_mask;
	struct sentinel *sentinel;
	
	filename = split_pathname(wpt, &dirname);
	sent = watchpoint_install(dirname, NULL);

	getevt("create", &ev_mask);
	hp = handler_alloc(ev_mask);
	hp->run = sentinel_handler_run;
	hp->free = sentinel_handler_free;

	sentinel = emalloc(sizeof(*sentinel));
	sentinel->watchpoint = wpt;
	sentinel->hp = hp;
	watchpoint_ref(wpt);
	
	hp->data = sentinel;
	
	filpatlist_add_exact(&hp->fnames, filename);
	handler_list_append(sent->handler_list, hp);
	unsplit_pathname(wpt);
	diag(LOG_NOTICE, _("installing CREATE sentinel for %s"), wpt->dirname);
	return watchpoint_init(sent);
}
	
int 
watchpoint_init(struct watchpoint *wpt)
{
	struct stat st;
	event_mask mask = { 0, 0 };
	struct handler *hp;
	handler_iterator_t itr;	
	int wd;

	debug(1, (_("creating watcher %s"), wpt->dirname));

	if (stat(wpt->dirname, &st)) {
		if (errno == ENOENT) {
			return watchpoint_install_sentinel(wpt);
		} else {
			diag(LOG_ERR, _("cannot set watcher on %s: %s"),
			     wpt->dirname, strerror(errno));
			return 1;
		}
	}

	wpt->isdir = S_ISDIR(st.st_mode);
	
	for_each_handler(wpt, itr, hp) {
		mask.sys_mask |= hp->ev_mask.sys_mask;
		mask.gen_mask |= hp->ev_mask.gen_mask;
	}
	
	wd = sysev_add_watch(wpt, mask);
	if (wd == -1) {
		diag(LOG_ERR, _("cannot set watcher on %s: %s"),
		     wpt->dirname, strerror(errno));
		return 1;
	}

	wpt->wd = wd;

	return 0;
}

static int watch_subdirs(struct watchpoint *parent, int notify);

int
subwatcher_create(struct watchpoint *parent, const char *dirname,
		  int notify)
{
	struct watchpoint *wpt;
	int inst;
	
	wpt = watchpoint_install(dirname, &inst);
	if (!inst)
		return -1;

	wpt->handler_list = handler_list_copy(parent->handler_list);
	wpt->parent = parent;
	
	if (parent->depth == -1)
		wpt->depth = parent->depth;
	else if (parent->depth)
		wpt->depth = parent->depth - 1;
	else
		wpt->depth = 0;
	
	if (watchpoint_init(wpt)) {
		//FIXME watchpoint_free(wpt);
		return -1;
	}

	return 1 + watch_subdirs(wpt, notify);
}

/* Deliver GENEV_CREATE event */
void
deliver_ev_create(struct watchpoint *wp, const char *dirname, const char *name)
{
	event_mask m = { GENEV_CREATE, 0 };
	struct handler *hp;
	handler_iterator_t itr;
	
	for_each_handler(wp, itr, hp) {
		if (handler_matches_event(hp, gen, GENEV_CREATE, name))
			hp->run(wp, &m, dirname, name, hp->data);
	}
}

/* Check if a new watcher must be created and create it if so.

   A watcher must be created if its parent's recursion depth has a non-null
   value.  If it has a negative value, which means "recursively watch new
   subdirectories without limit on their nesting level", it will be inherited
   by the new watcher.  Otherwise, the new watcher will inherit the parent's
   depth decreased by one, thus eventually cutting off creation of new
   watchers.

   Return 0 on success, -1 on error.
*/
int
check_new_watcher(const char *dir, const char *name)
{
	int rc;
	char *fname;
	struct stat st;
	struct watchpoint *parent;

	parent = watchpoint_lookup(dir);
	if (!parent || !parent->depth)
		return 0;
	
	fname = mkfilename(dir, name);
	if (!fname) {
		diag(LOG_ERR,
		     _("cannot create watcher %s/%s: not enough memory"),
		     dir, name);
		return -1;
	}

	if (stat(fname, &st)) {
		diag(LOG_ERR,
		     _("cannot create watcher %s/%s, stat failed: %s"),
		     dir, name, strerror(errno));
		rc = -1;
	} else if (S_ISDIR(st.st_mode)) {
		deliver_ev_create(parent, parent->dirname, name);
		rc = subwatcher_create(parent, fname, 1);
	} else
		rc = 0;
	free(fname);
	return rc;
}

int
watchpoint_pattern_match(struct watchpoint *wpt, const char *file_name)
{
	struct handler *hp;
	handler_iterator_t itr;

	for_each_handler(wpt, itr, hp) {
		if (filpatlist_match(hp->fnames, file_name) == 0)
			return 0;
	}
	return 1;
}

/* Recursively scan subdirectories of parent and add them to the
   watcher list, as requested by the parent's recursion depth value. */
static int
watch_subdirs(struct watchpoint *parent, int notify)
{
	DIR *dir;
	struct dirent *ent;
	int filemask;
	int total = 0;

	if (!parent->isdir)
		return 0;

	filemask = sysev_filemask(parent);
	if (parent->depth)
		filemask |= S_IFDIR;
	if (!filemask)
		return 0;
	
	dir = opendir(parent->dirname);
	if (!dir) {
		diag(LOG_ERR, _("cannot open directory %s: %s"),
		     parent->dirname, strerror(errno));
		return 0;
	}

	while (ent = readdir(dir)) {
		struct stat st;
		char *dirname;
		
		if (ent->d_name[0] == '.' &&
		    (ent->d_name[1] == 0 ||
		     (ent->d_name[1] == '.' && ent->d_name[2] == 0)))
			continue;
		
		dirname = mkfilename(parent->dirname, ent->d_name);
		if (!dirname) {
			diag(LOG_ERR,
			     _("cannot stat %s/%s: not enough memory"),
			     parent->dirname, ent->d_name);
			continue;
		}
		if (stat(dirname, &st)) {
			diag(LOG_ERR, _("cannot stat %s: %s"),
			     dirname, strerror(errno));
		} else if (watchpoint_pattern_match(parent, ent->d_name)
			   == 0) {
			if (notify)
				deliver_ev_create(parent, parent->dirname,
						  ent->d_name);
			if (st.st_mode & filemask) {
				int rc = subwatcher_create(parent, dirname,
							   notify);
				if (rc > 0)
					total += rc;
			}
		}
		free(dirname);
	}
	closedir(dir);
	return total;
}


static int
setwatcher(void *ent, void *data)
{
	struct wpref *wpref = (struct wpref *) ent;
	struct watchpoint *wpt = wpref->wpt;
	
	if (wpt->wd == -1 && watchpoint_init(wpt) == 0)
		watch_subdirs(wpt, 0);
	return 0;
}

static int
checkwatcher(void *ent, void *data)
{
	struct wpref *wpref = (struct wpref *) ent;
	struct watchpoint *wpt = wpref->wpt;
	return wpt->wd >= 0;
}
	
void
setup_watchers(void)
{
	sysev_init();
	if (grecs_symtab_count(nametab) == 0) {
		diag(LOG_CRIT, _("no event handlers configured"));
		exit(1);
	}
	grecs_symtab_foreach(nametab, setwatcher, NULL);
	if (!grecs_symtab_foreach(nametab, checkwatcher, NULL)) {
		diag(LOG_CRIT, _("no event handlers installed"));
		exit(2);
	}
}

static int
stopwatcher(void *ent, void *data)
{
	struct wpref *wpref = (struct wpref *) ent;
	struct watchpoint *wpt = wpref->wpt;
	if (wpt->wd != -1) {
		debug(1, (_("removing watcher %s"), wpt->dirname));
		sysev_rm_watch(wpt);
	}
	return 0;
}

void
shutdown_watchers(void)
{
	grecs_symtab_foreach(nametab, stopwatcher, NULL);
	grecs_symtab_clear(nametab);
}


char *
split_pathname(struct watchpoint *dp, char **dirname)
{
	char *p = strrchr(dp->dirname, '/');
	if (p) {
		dp->split_p = p;
		*p++ = 0;
		*dirname = dp->dirname;
	} else {
		p = dp->dirname;
		*dirname = ".";
	}
	return p;
}

void
unsplit_pathname(struct watchpoint *dp)
{
	if (dp->split_p) {
		*dp->split_p = '/';
		dp->split_p = NULL;
	}
}
