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
#include <grecs.h>
#include <pwd.h>
#include <grp.h>

static struct transtab kwpri[] = {
	{ "emerg", LOG_EMERG },
	{ "alert", LOG_ALERT },
	{ "crit", LOG_CRIT },
	{ "err", LOG_ERR },
	{ "warning", LOG_WARNING },
	{ "notice", LOG_NOTICE },
	{ "info", LOG_INFO },
	{ "debug", LOG_DEBUG },
	{ NULL }
};

static struct transtab kwfac[] = {
	{ "user",    LOG_USER },
	{ "daemon",  LOG_DAEMON },
	{ "auth",    LOG_AUTH },
	{ "authpriv",LOG_AUTHPRIV },
	{ "mail",    LOG_MAIL },
	{ "cron",    LOG_CRON },
	{ "local0",  LOG_LOCAL0 },
	{ "local1",  LOG_LOCAL1 },
	{ "local2",  LOG_LOCAL2 },
	{ "local3",  LOG_LOCAL3 },
	{ "local4",  LOG_LOCAL4 },
	{ "local5",  LOG_LOCAL5 },
	{ "local6",  LOG_LOCAL6 },
	{ "local7",  LOG_LOCAL7 },
	{ NULL }
};

int
get_facility(const char *arg)
{
	int f;
	char *p;

	errno = 0;
	f = strtoul (arg, &p, 0);
	if (*p == 0 && errno == 0)
		return f;
	if (trans_strtotok(kwfac, arg, &f)) {
		diag(LOG_CRIT, _("unknown syslog facility: %s"), arg);
		exit(1);
	}
	return f;
}

int
get_priority(const char *arg)
{
	int f;
	char *p;

	errno = 0;
	f = strtoul (arg, &p, 0);
	if (*p == 0 && errno == 0)
		return f;
	if (trans_strtotok(kwpri, arg, &f)) {
		diag(LOG_CRIT, _("unknown syslog priority: %s"), arg);
		exit(1);
	}
	return f;
}

#define ASSERT_SCALAR(cmd, locus)					\
	if ((cmd) != grecs_callback_set_value) {			\
		grecs_error(locus, 0, _("unexpected block statement"));	\
		return 1;						\
	}

int
assert_grecs_value_type(grecs_locus_t *locus,
			const grecs_value_t *value, int type)
{
	if (GRECS_VALUE_EMPTY_P(value)) {
		grecs_error(locus, 0, _("expected %s"),
			    grecs_data_type_string(type));
		return 1;
	}
	if (value->type != type) {
		grecs_error(locus, 0, _("expected %s, but found %s"),
			    grecs_data_type_string(type),
			    grecs_data_type_string(value->type));
		return 1;
	}
	return 0;
}

static int
cb_syslog_facility(enum grecs_callback_command cmd, grecs_node_t *node,
		   void *varptr, void *cb_data)
{
	grecs_locus_t *locus = &node->locus;
	grecs_value_t *value = node->v.value;
	int fac;

	ASSERT_SCALAR(cmd, locus);
	if (assert_grecs_value_type(&value->locus, value, GRECS_TYPE_STRING))
		return 1;

	if (trans_strtotok(kwfac, value->v.string, &fac))
		grecs_error(&value->locus, 0,
			    _("unknown syslog facility `%s'"),
			    value->v.string);
	else
		*(int*)varptr = fac;
	return 0;
}

static struct grecs_keyword syslog_kw[] = {
	{ "facility",
	  N_("name"),
	  N_("Set syslog facility. Arg is one of the following: user, daemon, "
	     "auth, authpriv, mail, cron, local0 through local7 "
	     "(case-insensitive), or a facility number."),
	  grecs_type_string, GRECS_DFLT,
	  &facility, 0, cb_syslog_facility },
	{ "tag", N_("string"), N_("Tag syslog messages with this string"),
	  grecs_type_string, GRECS_DFLT,
	  &tag },
	{ "print-priority", N_("arg"),
	  N_("Prefix each message with its priority"),
	  grecs_type_bool, GRECS_DFLT,
	  &syslog_include_prio },
	{ NULL },
};

struct eventconf {
	struct grecs_list *pathlist;
	event_mask ev_mask;
	filpatlist_t fpat;
	struct prog_handler prog_handler;
};

static struct eventconf eventconf;

static void
eventconf_init(void)
{
	memset(&eventconf, 0, sizeof eventconf);
	eventconf.prog_handler.timeout = DEFAULT_TIMEOUT;
}

static void
eventconf_free(void)
{
	grecs_list_free(eventconf.pathlist);
	prog_handler_free(&eventconf.prog_handler);
	filpatlist_destroy(&eventconf.fpat);
}

void
eventconf_flush(grecs_locus_t *loc)
{
	struct grecs_list_entry *ep;
	struct handler *hp = prog_handler_alloc(eventconf.ev_mask,
						eventconf.fpat,
						&eventconf.prog_handler);

	for (ep = eventconf.pathlist->head; ep; ep = ep->next) {
		struct pathent *pe = ep->data;
		struct watchpoint *wpt;
		int isnew;
		
		wpt = watchpoint_install(pe->path, &isnew);
		if (!wpt)
			abort();
		if (!isnew && wpt->depth != pe->depth)
			grecs_error(loc, 0,
				    _("%s: recursion depth does not match previous definition"),
				    pe->path);
		wpt->depth = pe->depth;
		handler_list_append(wpt->handler_list, hp);
	}
	grecs_list_free(eventconf.pathlist);
	eventconf_init();
}

static int
cb_watcher(enum grecs_callback_command cmd, grecs_node_t *node,
	   void *varptr, void *cb_data)
{
	int err = 0;
	
	switch (cmd) {
	case grecs_callback_section_begin:
		eventconf_init();
		break;
	case grecs_callback_section_end:
		if (!eventconf.pathlist) {
			grecs_error(&node->locus, 0, _("no paths configured"));
			++err;
		}
		if (!eventconf.prog_handler.command) {
			grecs_error(&node->locus, 0,
				    _("no command configured"));
			++err;
		}
		if (evtnullp(&eventconf.ev_mask))
			evtsetall(&eventconf.ev_mask);
		if (err == 0)
			eventconf_flush(&node->locus);
		else
			eventconf_free();
		break;
	case grecs_callback_set_value:
		grecs_error(&node->locus, 0,
			    _("invalid use of block statement"));
	}
	return 0;
}

static struct pathent *
pathent_alloc(char *s, long depth)
{
	size_t len = strlen(s);
	struct pathent *p = emalloc(sizeof(*p) + len);
	p->len = len;
	strcpy(p->path, s);
	p->depth = depth;
	return p;
}
	
static int
cb_path(enum grecs_callback_command cmd, grecs_node_t *node,
	void *varptr, void *cb_data)
{
        grecs_locus_t *locus = &node->locus;
	grecs_value_t *val = node->v.value;
	struct grecs_list **lpp = varptr, *lp;
	struct pathent *pe;
	char *s;
	long depth = 0;
		
	ASSERT_SCALAR(cmd, locus);

	switch (val->type) {
	case GRECS_TYPE_STRING:
		s = val->v.string;
		break;

	case GRECS_TYPE_ARRAY:
		if (assert_grecs_value_type(&val->v.arg.v[0]->locus,
					    val->v.arg.v[0],
					    GRECS_TYPE_STRING))
			return 1;
		if (assert_grecs_value_type(&val->v.arg.v[1]->locus,
					    val->v.arg.v[1],
					    GRECS_TYPE_STRING))
			return 1;
		if (strcmp(val->v.arg.v[1]->v.string, "recursive")) {
			grecs_error(&val->v.arg.v[1]->locus, 0,
				    _("expected \"recursive\" or end of statement"));
			return 1;
		}
		switch (val->v.arg.c) {
		case 2:
			depth = -1;
			break;
		case 3:
			if (grecs_string_convert(&depth, grecs_type_long,
						 val->v.arg.v[2]->v.string,
						 &val->v.arg.v[2]->locus))
				return 1;
			break;
		default:
			grecs_error(&val->v.arg.v[3]->locus, 0,
				    _("surplus argument"));
			return 1;
		}
		s = val->v.arg.v[0]->v.string;
		break;
	case GRECS_TYPE_LIST:
		grecs_error(locus, 0, _("unexpected list"));
		return 1;
	}
	pe = pathent_alloc(s, depth);
        if (*lpp)
		lp = *lpp;
	else {
		lp = _grecs_simple_list_create(1);
		*lpp = lp;
	}
	grecs_list_append(lp, pe);
	return 0;
}

static int
cb_eventlist(enum grecs_callback_command cmd, grecs_node_t *node,
	     void *varptr, void *cb_data)
{
        grecs_locus_t *locus = &node->locus;
	grecs_value_t *val = node->v.value;
	event_mask *mask = varptr;
	event_mask m;
	struct grecs_list_entry *ep;
	int i;
	
	ASSERT_SCALAR(cmd, locus);

	switch (val->type) {
	case GRECS_TYPE_STRING:
		if (getevt(val->v.string, &m)) {
			grecs_error(&val->locus, 0,
				    _("unrecognized event code"));
			return 1;
		}
		mask->gen_mask |= m.gen_mask;
		mask->sys_mask |= m.sys_mask;
		break;

	case GRECS_TYPE_ARRAY:
		for (i = 0; i < val->v.arg.c; i++) {
			if (assert_grecs_value_type(&val->v.arg.v[i]->locus,
						    val->v.arg.v[i],
						    GRECS_TYPE_STRING))
				return 1;
			if (getevt(val->v.arg.v[i]->v.string, &m)) {
				grecs_error(&val->v.arg.v[i]->locus, 0,
					    _("unrecognized event code"));
				return 1;
			}
			mask->gen_mask |= m.gen_mask;
			mask->sys_mask |= m.sys_mask;
		}
		break;
	case GRECS_TYPE_LIST:
		for (ep = val->v.list->head; ep; ep = ep->next)	{
			grecs_value_t *vp = ep->data;
			if (assert_grecs_value_type(&vp->locus, vp,
						    GRECS_TYPE_STRING))
				return 1;
			if (getevt(vp->v.string, &m)) {
				grecs_error(&vp->locus, 0,
					    _("unrecognized event code"));
				return 1;
			}
			mask->gen_mask |= m.gen_mask;
			mask->sys_mask |= m.sys_mask;
		}
		break;
	}
	return 0;
}

static int
membergid(gid_t gid, size_t gc, gid_t *gv)
{
	int i;
	for (i = 0; i < gc; i++)
		if (gv[i] == gid)
			return 1;
	return 0;
}

static void
get_user_groups(char *user, gid_t gid, size_t *pgidc, gid_t **pgidv)
{
	size_t gidc = 0, n = 0;
	gid_t *gidv = NULL;
	struct group *gr;

	n = 32;
	gidv = emalloc(n * sizeof(gidv[0]));
	gidv[0] = gid;
	gidc = 1;
	
	setgrent();
	while (gr = getgrent()) {
		char **p;
		for (p = gr->gr_mem; *p; p++)
			if (strcmp(*p, user) == 0) {
				if (n == gidc) {
					n += 32;
					gidv = erealloc(gidv,
							n * sizeof(gidv[0]));
				}
				if (!membergid(gr->gr_gid, gidc, gidv))
					gidv[gidc++] = gr->gr_gid;
			}
	}
	endgrent();
	*pgidc = gidc;
	*pgidv = gidv;
}

static int
cb_user(enum grecs_callback_command cmd, grecs_node_t *node,
	void *varptr, void *cb_data)
{
        grecs_locus_t *locus = &node->locus;
	grecs_value_t *val = node->v.value;
	struct passwd *pw;
	struct group *gr;
	grecs_value_t *uv, *gv = NULL;
	gid_t gid;
	
	ASSERT_SCALAR(cmd, locus);
	switch (val->type) {
	case GRECS_TYPE_STRING:
		uv = val;
		break;
		
	case GRECS_TYPE_ARRAY:
		if (assert_grecs_value_type(&val->v.arg.v[0]->locus,
					    val->v.arg.v[0],
					    GRECS_TYPE_STRING))
			return 1;
		if (assert_grecs_value_type(&val->v.arg.v[1]->locus,
					    val->v.arg.v[1],
					    GRECS_TYPE_STRING))
			return 1;
		if (val->v.arg.c > 2) {
			grecs_locus_t loc;
			loc.beg = val->v.arg.v[2]->locus.beg;
			loc.end = val->v.arg.v[val->v.arg.c - 1]->locus.end;
			grecs_error(&loc, 0, _("surplus arguments"));
			return 1;
		}
		uv = val->v.arg.v[0];
		gv = val->v.arg.v[1];
		break;

	case GRECS_TYPE_LIST:
		grecs_error(locus, 0, _("unexpected list"));
		return 1;
	}

	pw = getpwnam(uv->v.string);
	if (!pw) {
		grecs_error(&uv->locus, 0, _("no such user"));
		return 1;
	}

	if (gv) {
		gr = getgrnam(gv->v.string);
		if (!gr) {
			grecs_error(&gv->locus, 0, _("no such group"));
			return 1;
		}
		gid = gr->gr_gid;
	} else
		gid = pw->pw_gid;

	eventconf.prog_handler.uid = pw->pw_uid;
	get_user_groups(uv->v.string, gid,
			&eventconf.prog_handler.gidc, &eventconf.prog_handler.gidv);
	
	return 0;
}

static int
cb_option(enum grecs_callback_command cmd, grecs_node_t *node,
	  void *varptr, void *cb_data)
{
        grecs_locus_t *locus = &node->locus;
	grecs_value_t *val = node->v.value;
	struct grecs_list_entry *ep;
	
	ASSERT_SCALAR(cmd, locus);
	if (assert_grecs_value_type(&val->locus, val, GRECS_TYPE_LIST))
		return 1;

	for (ep = val->v.list->head; ep; ep = ep->next)	{
		grecs_value_t *vp = ep->data;
		if (assert_grecs_value_type(&vp->locus, vp,
					    GRECS_TYPE_STRING))
			return 1;
		if (strcmp(vp->v.string, "nowait") == 0)
			eventconf.prog_handler.flags |= HF_NOWAIT;
		else if (strcmp(vp->v.string, "wait") == 0)
			eventconf.prog_handler.flags &= ~HF_NOWAIT;
		else if (strcmp(vp->v.string, "stdout") == 0)
			eventconf.prog_handler.flags |= HF_STDOUT;
		else if (strcmp(vp->v.string, "stderr") == 0)
			eventconf.prog_handler.flags |= HF_STDERR;
		else if (strcmp(vp->v.string, "shell") == 0)
			eventconf.prog_handler.flags |= HF_SHELL;
		else 
			grecs_error(&vp->locus, 0, _("unrecognized option"));
	}
	return 0;
}
	
static int
cb_environ(enum grecs_callback_command cmd, grecs_node_t *node,
	   void *varptr, void *cb_data)
{
        grecs_locus_t *locus = &node->locus;
	grecs_value_t *val = node->v.value;
	struct grecs_list_entry *ep;
	int i, j;
	
	ASSERT_SCALAR(cmd, locus);
	switch (val->type) {
	case GRECS_TYPE_STRING:
		if (assert_grecs_value_type(&val->locus, val,
					    GRECS_TYPE_STRING))
			return 1;
		i = prog_handler_envrealloc(&eventconf.prog_handler, 1);
		eventconf.prog_handler.env[i] = estrdup(val->v.string);
		eventconf.prog_handler.env[i+1] = NULL;
		break;
		
	case GRECS_TYPE_ARRAY:
		j = prog_handler_envrealloc(&eventconf.prog_handler, val->v.arg.c);
		for (i = 0; i < val->v.arg.c; i++, j++) {
			if (assert_grecs_value_type(&val->v.arg.v[i]->locus,
						    val->v.arg.v[i],
						    GRECS_TYPE_STRING))
				return 1;
			eventconf.prog_handler.env[j] = estrdup(val->v.arg.v[i]->v.string);
		}
		eventconf.prog_handler.env[j] = NULL;
		break;

	case GRECS_TYPE_LIST:
		j = prog_handler_envrealloc(&eventconf.prog_handler,
					    val->v.list->count);
		for (ep = val->v.list->head; ep; ep = ep->next, j++) {
			grecs_value_t *vp = ep->data;
			if (assert_grecs_value_type(&vp->locus, vp,
						    GRECS_TYPE_STRING))
				return 1;
			eventconf.prog_handler.env[j] = estrdup(vp->v.string);
		}
		eventconf.prog_handler.env[j] = NULL;
	}
	return 0;
}		

static int
file_name_pattern(filpatlist_t *fptr, grecs_value_t *val)
{
	if (assert_grecs_value_type(&val->locus, val, GRECS_TYPE_STRING))
		return 1;
	return filpatlist_add(fptr, val->v.string, &val->locus);
}

static int
cb_file_pattern(enum grecs_callback_command cmd, grecs_node_t *node,
		void *varptr, void *cb_data)
{
	grecs_value_t *val = node->v.value;
	filpatlist_t *fpat = varptr;
	struct grecs_list_entry *ep;
	int i;
	
	ASSERT_SCALAR(cmd, &node->locus);

	switch (val->type) {
	case GRECS_TYPE_STRING:
		file_name_pattern(fpat, val);
		break;

	case GRECS_TYPE_ARRAY:
		for (i = 0; i < val->v.arg.c; i++)
			if (file_name_pattern(fpat, val->v.arg.v[i]))
				break;
		break;

	case GRECS_TYPE_LIST:
		for (ep = val->v.list->head; ep; ep = ep->next)
			if (file_name_pattern(fpat,
					      (grecs_value_t *) ep->data))
				break;
		break;
	}

	return 0;
}

static struct grecs_keyword watcher_kw[] = {
	{ "path", NULL, N_("Pathname to watch"),
	  grecs_type_string, GRECS_DFLT, &eventconf.pathlist, 0,
	  cb_path },
	{ "event", NULL, N_("Events to watch for"),
	  grecs_type_string, GRECS_LIST, &eventconf.ev_mask, 0,
	  cb_eventlist },
	{ "file", N_("regexp"), N_("Files to watch for"),
	  grecs_type_string, GRECS_LIST, &eventconf.fpat, 0,
	  cb_file_pattern },
	{ "command", NULL, N_("Command to execute on event"),
	  grecs_type_string, GRECS_DFLT, &eventconf.prog_handler.command },
	{ "user", N_("name"), N_("Run command as this user"),
	  grecs_type_string, GRECS_DFLT, NULL, 0,
	  cb_user },
	{ "timeout", N_("seconds"), N_("Timeout for the command"),
	  grecs_type_uint, GRECS_DFLT, &eventconf.prog_handler.timeout },
	{ "option", NULL, N_("List of additional options"),
	  grecs_type_string, GRECS_LIST, NULL, 0,
	  cb_option },
	{ "environ", N_("<arg: string> <arg: string>..."),
	  N_("Modify environment"),
	  grecs_type_string, GRECS_DFLT, NULL, 0,
	  cb_environ },
	{ NULL }
};

static struct grecs_keyword direvent_kw[] = {
	{ "user", NULL, N_("Run as this user"),
	  grecs_type_string, GRECS_DFLT, &user },
	{ "foreground", NULL, N_("Run in foreground"),
	  grecs_type_bool, GRECS_DFLT, &foreground },
	{ "pidfile", N_("file"), N_("Set pid file name"),
	  grecs_type_string, GRECS_DFLT, &pidfile },
	{ "syslog", NULL, N_("Configure syslog logging"),
	  grecs_type_section, GRECS_DFLT, NULL, 0, NULL, NULL, syslog_kw },
	{ "debug", N_("level"), N_("Set debug level"),
	  grecs_type_int, GRECS_DFLT, &debug_level },
	{ "watcher", NULL, N_("Configure event watcher"),
	  grecs_type_section, GRECS_DFLT, NULL, 0,
	  cb_watcher, NULL, watcher_kw },
	{ NULL }
};
	

void
config_help()
{
	static char docstring[] =
		N_("Configuration file structure for direvent.\n"
		   "For more information, use `info direvent configuration'.");
	grecs_print_docstring(docstring, 0, stdout);
	grecs_print_statement_array(direvent_kw, 1, 0, stdout);
}

void
config_init(void)
{
	grecs_include_path_setup(INCLUDE_PATH_ARGS, NULL);
}

void
config_parse(char const *conffile)
{
	struct grecs_node *tree;

	grecs_parser_options = GRECS_OPTION_QUOTED_STRING_CONCAT;
	tree = grecs_parse(conffile);
	if (!tree)
		exit(1);
	if (grecs_tree_process(tree, direvent_kw))
		exit(1);
	
}
