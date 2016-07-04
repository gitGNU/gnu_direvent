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
#include <sys/event.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>

struct transtab sysev_transtab[] = {
	{ "DELETE", NOTE_DELETE },
	{ "WRITE",  NOTE_WRITE  },
	{ "EXTEND", NOTE_EXTEND },
	{ "ATTRIB", NOTE_ATTRIB },
	{ "LINK",   NOTE_LINK   },
	{ "RENAME", NOTE_RENAME },
	{ "REVOKE", NOTE_REVOKE },
	{ NULL }
};


static int kq;
static struct kevent *evtab;
static struct kevent *chtab;
static int chcnt;
static int chclosed = -1;

event_mask genev_xlat[] = {
	{ GENEV_CREATE, 0 },
	{ GENEV_WRITE,  NOTE_WRITE|NOTE_EXTEND },
	{ GENEV_ATTRIB, NOTE_ATTRIB|NOTE_LINK },
	{ GENEV_DELETE, NOTE_DELETE|NOTE_RENAME|NOTE_REVOKE },
	{ 0 }
};

void
sysev_init()
{
	kq = kqueue();
	if (kq == -1) {
		diag(LOG_CRIT, "kqueue: %s", strerror(errno));
		exit(1);
	}
	evtab = calloc(sysconf(_SC_OPEN_MAX), sizeof(evtab[0]));
	chtab = calloc(sysconf(_SC_OPEN_MAX), sizeof(chtab[0]));
}

int
sysev_filemask(struct dirwatcher *dp)
{
	struct handler *h;

	for (h = dp->handler_list; h; h = h->next) {
		if (h->ev_mask.sys_mask)
			return S_IFMT;
	}
	return 0;
}

int
sysev_add_watch(struct dirwatcher *dwp, event_mask mask)
{
	int wd = open(dwp->dirname, O_RDONLY);
	if (wd >= 0) {
		struct stat st;
		int sysmask;
		
		if (fstat(wd, &st)) {
			close(wd);
			return -1;
		}
		dwp->file_mode = st.st_mode;
		dwp->file_ctime = st.st_ctime;
		sysmask = mask.sys_mask;
		if (S_ISDIR(st.st_mode) && mask.gen_mask & GENEV_CREATE)
			sysmask |= NOTE_WRITE;
		EV_SET(chtab + chcnt, wd, EVFILT_VNODE,
		       EV_ADD | EV_ENABLE | EV_CLEAR, sysmask,
		       0, dwp);
		wd = chcnt++;
	}
	return wd;
}

void
sysev_rm_watch(struct dirwatcher *dwp)
{
	close(chtab[dwp->wd].ident);
	chtab[dwp->wd].ident = -1;
	if (chclosed == -1 || chclosed > dwp->wd)
		chclosed = dwp->wd;
}

static void
chclosed_elim()
{
	int i, j;
	
	if (chclosed == -1)
		return;

	for (i = chclosed, j = chclosed + 1; j < chcnt; j++)
		if (chtab[j].ident != -1) {
			struct dirwatcher *dwp;
			
			chtab[i] = chtab[j];
			dwp = chtab[i].udata;
			dwp->wd = i;
			i++;
		}
	chcnt = i;
	chclosed = -1;
}

static void
check_created(struct dirwatcher *dp)
{
	DIR *dir;
	struct dirent *ent;
	struct handler *h;

	dir = opendir(dp->dirname);
	if (!dir) {
		diag(LOG_ERR, "cannot open directory %s: %s",
		     dp->dirname, strerror(errno));
		return;
	}

	while (ent = readdir(dir)) {
		struct stat st;
		char *pathname;
		
		if (ent->d_name[0] == '.' &&
		    (ent->d_name[1] == 0 ||
		     (ent->d_name[1] == '.' && ent->d_name[2] == 0)))
			continue;
		
		pathname = mkfilename(dp->dirname, ent->d_name);
		if (!pathname) {
			diag(LOG_ERR, "cannot stat %s/%s: not enough memory",
			     dp->dirname, ent->d_name);
			continue;
		}

		if (stat(pathname, &st)) {
			diag(LOG_ERR, "cannot stat %s: %s",
			     pathname, strerror(errno));
		/* If ok, first see if the file is newer than the last
		   directory scan.  If not, there is still a chance
		   the file is new (the timestamp precision leaves a
		   time window long enough for a file to be created)
		   so try the more expensive hash lookup to see if we
		   know about that file.  If the file is new, register
		   a watcher for it. */
		} else if (st.st_ctime > dp->file_ctime ||
			   !dirwatcher_lookup(pathname)) {
			deliver_ev_create(dp, ent->d_name);
			subwatcher_create(dp, pathname,
					  S_ISDIR(st.st_mode), 1);
			dp->file_ctime = st.st_ctime;
		}
		free(pathname);
	}
	closedir(dir);
}

static void
process_event(struct kevent *ep)
{
	struct dirwatcher *dp = ep->udata;
	struct handler *h;
	event_mask m;
	char *filename, *dirname;
	
	if (!dp) {
		diag(LOG_NOTICE, "unrecognized event %x", ep->fflags);
		return;
	}

	ev_log(ep->fflags, dp);

	if (S_ISDIR(dp->file_mode)) {
		/* Check if new files have appeared. */
		if (ep->fflags & NOTE_WRITE)
			check_created(dp);
		return;
	}

	filename = split_pathname(dp, &dirname);
	for (h = dp->handler_list; h; h = h->next) {
		if (handler_matches_event(h, sys, ep->fflags, filename)) {
			run_handler(h,
				    event_mask_init(&m, ep->fflags, &h->ev_mask),
				    dirname, filename);
		}
	}
	unsplit_pathname(dp);
	
	if (ep->fflags & (NOTE_DELETE|NOTE_RENAME)) {
		debug(1, ("%s deleted", dp->dirname));
		dirwatcher_destroy(dp);
		return;
	}
}	


int
sysev_select()
{
	int i, n;
	
	chclosed_elim();
	n = kevent(kq, chtab, chcnt, evtab, chcnt, NULL);
	if (n == -1) {
		if (errno == EINTR) {
			if (signo == SIGCHLD || signo == SIGALRM)
				return 0;
			diag(LOG_NOTICE, "got signal %d", signo);
		}
		diag(LOG_ERR, "kevent: %s", strerror(errno));
		return 1;
	} 

	for (i = 0; i < n; i++) 
		process_event(&evtab[i]);

	return 0;
}
		
