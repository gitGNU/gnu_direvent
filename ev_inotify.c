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
#include "dircond.h"
#include <signal.h>
#include <sys/inotify.h>


/* Event codes */
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
evsys_name_to_code(const char *name)
{
	int i;

	for (i = 0; events[i].evname; i++) {
		if (strcmp(events[i].evname, name) == 0)
			return events[i].evcode;
	}
	return 0;
}

const char *
evsys_code_to_name(int code)
{
	int i;

	for (i = 0; events[i].evname; i++) {
		if (events[i].evcode & code)
			return events[i].evname;
	}
	return NULL;
}

static int ifd;
int evsys_filemask = 0;

void
evsys_init()
{
	ifd = inotify_init();
	if (ifd == -1) {
		diag(LOG_CRIT, "inotify_init: %s", strerror(errno));
		exit(1);
	}
}

int
evsys_add_watch(struct dirwatcher *dwp, int mask)
{
	return inotify_add_watch(ifd, dwp->dirname, mask);
}

void
evsys_rm_watch(struct dirwatcher *dwp)
{
	inotify_rm_watch(ifd, dwp->wd);
}

static void
process_event(struct inotify_event *ep)
{
	struct dirwatcher *dp;
	struct handler *h;
				
	dp = dirwatcher_lookup_wd(ep->wd);
	if (ep->mask & IN_IGNORED)
		return;
	else if (ep->mask & IN_Q_OVERFLOW) {
		diag(LOG_NOTICE,
		     "event queue overflow");
		return;
	} else if (ep->mask & IN_UNMOUNT) {
		/* FIXME: not sure if there's
		   anything to do. Perhaps we should
		   deregister the watched dirs that
		   were located under the mountpoint
		*/
		return;
	} else if (!dp) {
		if (ep->name)
			diag(LOG_NOTICE, "unrecognized event %x"
			     "for %s", ep->mask, ep->name);
		else
			diag(LOG_NOTICE,
			     "unrecognized event %x", ep->mask);
		return;
	} else if (ep->mask & IN_CREATE) {
		debug(1, ("%s/%s created", dp->dirname, ep->name));
		check_new_watcher(dp->dirname, ep->name);
	} else if (ep->mask & (IN_DELETE|IN_MOVED_FROM)) {
		debug(1, ("%s/%s deleted", dp->dirname, ep->name));
		remove_watcher(dp->dirname, ep->name);
	}

	ev_log(ep, dp);
	
	for (h = dp->handler_list; h; h = h->next) {
		if (h->ev_mask & ep->mask)
			run_handler(dp, h, ep->mask, ep->name);
	}
}	

void
evsys_loop()
{
	char buffer[4096];

	/* Main loop */
	while (1) {
		struct inotify_event *ep;
		size_t size;
		ssize_t rdbytes;

		process_timeouts();
		process_cleanup(0);

		rdbytes = read(ifd, buffer, sizeof(buffer));
		if (rdbytes == -1) {
			if (errno == EINTR) {
				if (signo == SIGCHLD || signo == SIGALRM)
					continue;
				diag(LOG_NOTICE, "got signal %d", signo);
				break;
			}
			
			diag(LOG_NOTICE, "read failed: %s", strerror(errno));
			break;
		}
		
		ep = (struct inotify_event *) buffer;
		while (rdbytes) {
			if (ep->wd >= 0)
				process_event(ep);
			size = sizeof(*ep) + ep->len;
			ep = (struct inotify_event *) ((char*) ep + size);
			rdbytes -= size;
		}
	}
}
