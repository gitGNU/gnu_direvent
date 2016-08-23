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
#include <fnmatch.h>
#include <grecs.h>

static void
filename_pattern_free(void *p)
{
	struct filename_pattern *pat = p;
	switch (pat->type) {
	case PAT_EXACT:
	case PAT_GLOB:
		free(pat->v.glob);
		break;
	case PAT_REGEX:
		regfree(&pat->v.re);
	}
	free(pat);
}

struct filpatlist {
	grecs_list_ptr_t list;
};

static int
is_glob(char const *str)
{
	return strcspn(str, "[]*?") < strlen(str);
}

void
filpatlist_add_pattern(filpatlist_t *fptr, struct filename_pattern *pat)
{
	grecs_list_ptr_t list;
	if (!*fptr) {
		*fptr = emalloc(sizeof(*fptr));
		(*fptr)->list = grecs_list_create();
		(*fptr)->list->free_entry = filename_pattern_free;
	}
	list = (*fptr)->list;
	grecs_list_append(list, pat);
}
	
void
filpatlist_add_exact(filpatlist_t *fptr, char const *arg)
{
	struct filename_pattern *pat = emalloc(sizeof(*pat));
	
	pat->neg = 0;
	pat->type = PAT_EXACT;
	pat->v.glob = estrdup(arg);
	filpatlist_add_pattern(fptr, pat);
}	

int
filpatlist_add(filpatlist_t *fptr, char const *arg, grecs_locus_t *loc)
{
	int flags = REG_EXTENDED|REG_NOSUB;
	struct filename_pattern *pat;
	
	pat = emalloc(sizeof(*pat));
	if (*arg == '!') {
		pat->neg = 1;
		++arg;
	} else
		pat->neg = 0;
	if (arg[0] == '/') {
		int rc;
		char *q, *p;

		pat->type = PAT_REGEX;
		
		p = strchr(arg+1, '/');
		if (!p) {
			grecs_error(loc, 0, _("unterminated regexp"));
			free(pat);
			return 1;
		}
		for (q = p + 1; *q; q++) {
			switch (*q) {
			case 'b':
				flags &= ~REG_EXTENDED;
				break;
			case 'i':
				flags |= REG_ICASE;
				break;
			default:
				grecs_error(loc, 0,
					    _("unrecognized flag: %c"), *q);
				free(pat);
				return 1;
			}
		}
		
		*p = 0;
		rc = regcomp(&pat->v.re, arg + 1, flags);
		*p = '/';

		if (rc) {
			char errbuf[128];
			regerror(rc, &pat->v.re, errbuf, sizeof(errbuf));
			grecs_error(loc, 0, "%s", errbuf);
			filename_pattern_free(pat);
			return 1;
		}
	} else {
		pat->type = is_glob(arg) ? PAT_GLOB : PAT_EXACT;
		pat->v.glob = estrdup(arg);
	}
	filpatlist_add_pattern(fptr, pat);
	return 0;
}

void
filpatlist_destroy(filpatlist_t *fptr)
{
	if (fptr && *fptr) {
		grecs_list_free((*fptr)->list);
		free(*fptr);
		*fptr = NULL;
	}
}

int
filpatlist_is_empty(filpatlist_t fp)
{
	if (!fp)
		return 1;
	return grecs_list_size(fp->list) == 0;
}

int
filpatlist_match(filpatlist_t fp, const char *name)
{
	struct grecs_list_entry *ep;

	if (!fp || !fp->list)
		return 0;
	for (ep = fp->list->head; ep; ep = ep->next) {
		struct filename_pattern *pat = ep->data;
		int rc;
		
		switch (pat->type) {
		case PAT_EXACT:
			rc = strcmp(pat->v.glob, name);
			break;
		case PAT_GLOB:
			rc = fnmatch(pat->v.glob, name, FNM_PATHNAME);
			break;
		case PAT_REGEX:
			rc = regexec(&pat->v.re, name, 0, NULL, 0);
			break;
		}
		if (pat->neg)
			rc = !rc;
		if (rc == 0)
			return 0;
	}
	return 1;
}
