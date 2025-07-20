#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define PR_FMT "session"
#define PR_DOMAIN DBG_SESSION

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/fstack.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/utils.h"

static void delete_tasks(struct uftrace_session_link *sessions);

/**
 * read_session_map - read memory mappings in a session map file
 * @dirname: directory name of the session
 * @addr_space: address space to keep the memory mapping
 * @sid: session id
 *
 * This function reads mapping data from a session map file and
 * construct the address space for a session to resolve symbols
 * in libraries.
 */
void read_session_map(char *dirname, struct uftrace_sym_info *sinfo, char *sid)
{
	FILE *fp;
	char buf[PATH_MAX];
	const char *last_libname = NULL;
	struct uftrace_mmap **maps = &sinfo->maps;
	struct uftrace_mmap *last_map = NULL;
	const char build_id_prefix[] = "build-id:";

	snprintf(buf, sizeof(buf), "%s/sid-%.*s.map", dirname, SESSION_ID_LEN, sid);
	fp = fopen(buf, "rb");
	if (fp == NULL)
		pr_err("cannot open maps file: %s", buf);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		uint64_t start, end;
		char prot[5];
		char path[PATH_MAX];
		char build_id[BUILD_ID_STR_SIZE + sizeof(build_id_prefix)];
		size_t namelen;
		struct uftrace_mmap *map;

		/* prevent to reuse previous iteration's result */
		build_id[0] = '\0';

		/* skip anon mappings */
		if (sscanf(buf, "%" PRIx64 "-%" PRIx64 " %s %*x %*x:%*x %*d %s %s", &start, &end,
			   prot, path, build_id) < 4) {
			pr_dbg("sscanf failed\n");
			continue;
		}

		/* skip the [stack] mapping */
		if (path[0] == '[') {
			if (strncmp(path, "[stack", 6) == 0)
				sinfo->kernel_base = guess_kernel_base(buf);
			continue;
		}

		/* use first mapping only (even if it's non-exec) */
		if (last_libname && !strcmp(last_libname, path)) {
			/* extend last_map to have all segments */
			last_map->end = end;
			continue;
		}

		namelen = ALIGN(strlen(path) + 1, 4);

		map = xzalloc(sizeof(*map) + namelen);

		map->start = start;
		map->end = end;
		map->len = namelen;

		memcpy(map->prot, prot, 4);
		memcpy(map->libname, path, namelen);
		map->libname[strlen(path)] = '\0';

		if (!strncmp(build_id, build_id_prefix, strlen(build_id_prefix))) {
			memcpy(map->build_id, build_id + strlen(build_id_prefix),
			       sizeof(build_id) - sizeof(build_id_prefix));
		}

		/* set mapping of main executable */
		if (sinfo->exec_map == NULL && sinfo->filename && !strcmp(path, sinfo->filename)) {
			sinfo->exec_map = map;
		}

		last_libname = map->libname;
		last_map = map;

		*maps = map;
		maps = &map->next;
	}
	fclose(fp);
}

/**
 * delete_session_map - free memory mappings in an address space
 * @addr_space: symbol table has the memory mapping
 *
 * This function releases mapping data in a symbol table which
 * was read by read_session_map().
 */
void delete_session_map(struct uftrace_sym_info *sinfo)
{
	struct uftrace_mmap *map, *tmp;

	map = sinfo->maps;
	while (map) {
		tmp = map->next;
		free(map);
		map = tmp;
	}

	sinfo->maps = NULL;
	sinfo->exec_map = NULL;
}

/**
 * update_session_map - rewrite map files to have build-id
 * @filename - name of map file
 *
 * This function updates @filename map file to add build-id at the end
 * of each line.
 */
void update_session_map(const char *filename)
{
	FILE *ifp, *ofp;
	char buf[PATH_MAX];
	const char build_id_prefix[] = "build-id:";

	ifp = fopen(filename, "r");
	if (ifp == NULL)
		pr_err("cannot open map file: %s", filename);

	snprintf(buf, sizeof(buf), "%s.tmp", filename);
	ofp = fopen(buf, "w");
	if (ofp == NULL)
		pr_err("cannot create new map file: %s", buf);

	while (fgets(buf, sizeof(buf), ifp) != NULL) {
		char path[PATH_MAX];
		char build_id[BUILD_ID_STR_SIZE];
		int len;

		len = strlen(buf);
		if (len > 0 && buf[len - 1] == '\n')
			buf[--len] = '\0';
		fwrite_all(buf, len, ofp);

		/* skip anon mappings */
		if (sscanf(buf, "%*x-%*x %*s %*x %*x:%*x %*d %s", path) != 1)
			goto next;

		/* skip the special mappings like [stack] */
		if (path[0] == '[')
			goto next;

		if (read_build_id(path, build_id, sizeof(build_id)) == 0)
			fprintf(ofp, " %s%s", build_id_prefix, build_id);

next:
		fputc('\n', ofp);
	}

	fclose(ifp);
	fclose(ofp);

	snprintf(buf, sizeof(buf), "%s.tmp", filename);
	if (rename(buf, filename) < 0)
		pr_err("cannot rename map file: %s", filename);
}

/**
 * create_session - create a new task session from session message
 * @sessions: session link to manage sessions and tasks
 * @msg: uftrace session message read from task file
 * @dirname: uftrace data directory name
 * @symdir: symbol directory name
 * @exename: executable name started this session
 * @sym_rel_addr: whether symbol table uses relative address
 * @needs_symtab: whether symbol table loading is needed
 * @needs_srcline: whether debug info loading is needed
 *
 * This function allocates a new session started by a task.  The new
 * session will be added to sessions tree sorted by pid and timestamp.
 * Also it loads symbol table and debug info if needed.
 */
void create_session(struct uftrace_session_link *sessions, struct uftrace_msg_sess *msg,
		    char *dirname, char *symdir, char *exename, bool sym_rel_addr,
		    bool needs_symtab, bool needs_srcline)
{
	struct uftrace_session *s;
	struct uftrace_task *t;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions->root.rb_node;

	while (*p) {
		parent = *p;
		s = rb_entry(parent, struct uftrace_session, node);

		if (s->pid > msg->task.pid)
			p = &parent->rb_left;
		else if (s->pid < msg->task.pid)
			p = &parent->rb_right;
		else if (s->start_time > msg->task.time)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	s = xzalloc(sizeof(*s) + msg->namelen + 1);

	memcpy(s->sid, msg->sid, sizeof(s->sid));
	s->start_time = msg->task.time;
	s->pid = msg->task.pid;
	s->tid = msg->task.tid;
	s->namelen = msg->namelen;
	memcpy(s->exename, exename, s->namelen);
	s->exename[s->namelen] = 0;
	INIT_LIST_HEAD(&s->dlopen_libs);

	pr_dbg2("new session: pid = %d, session = %.*s\n", s->pid, SESSION_ID_LEN, s->sid);

	if (needs_symtab) {
		s->sym_info.dirname = dirname;
		s->sym_info.filename = s->exename;
		s->sym_info.symdir = symdir;
		s->sym_info.flags = SYMTAB_FL_USE_SYMFILE | SYMTAB_FL_DEMANGLE;
		if (sym_rel_addr)
			s->sym_info.flags |= SYMTAB_FL_ADJ_OFFSET;
		if (strcmp(dirname, symdir))
			s->sym_info.flags |= SYMTAB_FL_SYMS_DIR;

		read_session_map(dirname, &s->sym_info, s->sid);

		load_module_symtabs(&s->sym_info);
		load_debug_info(&s->sym_info, needs_srcline);
	}

	if (sessions->first == NULL)
		sessions->first = s;

	t = find_task(sessions, s->tid);
	if (t) {
		strncpy(t->comm, uftrace_basename(exename), sizeof(t->comm));
		t->comm[sizeof(t->comm) - 1] = '\0';
	}

	rb_link_node(&s->node, parent, p);
	rb_insert_color(&s->node, &sessions->root);
}

static struct uftrace_session *find_session(struct uftrace_session_link *sessions, int pid,
					    uint64_t timestamp)
{
	struct uftrace_session *iter;
	struct uftrace_session *s = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions->root.rb_node;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_session, node);

		if (iter->pid > pid)
			p = &parent->rb_left;
		else if (iter->pid < pid)
			p = &parent->rb_right;
		else if (iter->start_time > timestamp)
			p = &parent->rb_left;
		else {
			s = iter;
			p = &parent->rb_right;
		}
	}

	return s;
}

/**
 * walk_sessions - iterates all session and invokes @callback
 * @sessions: session link to manage sessions and tasks
 * @callback: function to be called for each task
 * @arg: argument passed to the @callback
 *
 * This function traverses the task tree and invokes @callback with
 * @arg.  As the @callback returns a non-zero value, it'll stop and
 * return in the middle.
 */
void walk_sessions(struct uftrace_session_link *sessions, walk_sessions_cb_t callback, void *arg)
{
	struct rb_node *n = rb_first(&sessions->root);
	struct uftrace_session *s;

	while (n) {
		s = rb_entry(n, struct uftrace_session, node);

		if (callback(s, arg) != 0)
			break;

		n = rb_next(n);
	}
}

/**
 * get_session_from_sid - find a session using @sid
 * @sessions: session link to manage sessions and tasks
 * @sid: session ID
 *
 * This function returns a matching session or %NULL.
 */
struct uftrace_session *get_session_from_sid(struct uftrace_session_link *sessions, char sid[])
{
	struct rb_node *n = rb_first(&sessions->root);
	struct uftrace_session *s;

	while (n) {
		s = rb_entry(n, struct uftrace_session, node);

		if (memcmp(s->sid, sid, sizeof(s->sid)) == 0)
			return s;

		n = rb_next(n);
	}
	return NULL;
}

/**
 * session_add_dlopen - add dlopen'ed library to the mapping table
 * @sess: pointer to a current session
 * @timestamp: timestamp at the dlopen call
 * @base_addr: load address of text segment of the library
 * @libname: name of the library
 * @needs_srcline: whether debug info loading is needed
 *
 * This functions adds the info of a library which was loaded by dlopen.
 * Instead of creating a new session, it just adds the library information
 * to the @sess.
 */
void session_add_dlopen(struct uftrace_session *sess, uint64_t timestamp, unsigned long base_addr,
			const char *libname, bool needs_srcline)
{
	struct uftrace_dlopen_list *udl, *pos;
	char build_id[BUILD_ID_STR_SIZE];

	udl = xmalloc(sizeof(*udl));
	udl->time = timestamp;
	udl->base = base_addr;

	read_build_id(libname, build_id, sizeof(build_id));
	udl->mod = load_module_symtab(&sess->sym_info, libname, build_id);
	load_module_debug_info(udl->mod, sess->sym_info.symdir, needs_srcline);

	udl->filter_info.root = RB_ROOT;

	list_for_each_entry(pos, &sess->dlopen_libs, list) {
		if (pos->time > timestamp)
			break;
	}
	list_add_tail(&udl->list, &pos->list);
}

/**
 * session_find_dlsym - find symbol from dlopen'ed library
 * @sess: pointer to a current session
 * @timestamp: timestamp of the address
 * @addr: instruction address
 *
 * This functions find a matching symbol from a dlopen'ed library in
 * @sess using @addr.  The @timestamp is needed to determine which
 * library should be searched.
 */
struct uftrace_symbol *session_find_dlsym(struct uftrace_session *sess, uint64_t timestamp,
					  unsigned long addr)
{
	struct uftrace_dlopen_list *pos;
	struct uftrace_symbol *sym;

	list_for_each_entry_reverse(pos, &sess->dlopen_libs, list) {
		if (pos->time > timestamp)
			continue;

		if (pos->mod == NULL)
			continue;

		sym = find_sym(&pos->mod->symtab, addr - pos->base);
		if (sym)
			return sym;
	}

	return NULL;
}

struct uftrace_dlopen_list *session_find_dlopen(struct uftrace_session *sess, uint64_t timestamp,
						unsigned long addr)
{
	struct uftrace_dlopen_list *pos;
	struct uftrace_symbol *sym;

	list_for_each_entry_reverse(pos, &sess->dlopen_libs, list) {
		if (pos->time > timestamp)
			continue;

		if (pos->mod == NULL)
			continue;

		sym = find_sym(&pos->mod->symtab, addr - pos->base);
		if (sym)
			return pos;
	}

	return NULL;
}

void delete_session(struct uftrace_session *sess)
{
	struct uftrace_dlopen_list *udl, *tmp;

	list_for_each_entry_safe(udl, tmp, &sess->dlopen_libs, list) {
		list_del(&udl->list);
		uftrace_cleanup_filter(&udl->filter_info);
		free(udl);
	}

	finish_debug_info(&sess->sym_info);
	delete_session_map(&sess->sym_info);
	uftrace_cleanup_filter(&sess->filter_info);
	uftrace_cleanup_filter(&sess->fixups);
	free(sess);
}

/**
 * delete_sessions - free all resources in the @sessions
 * @sessions: session link to manage sessions and tasks
 *
 * This function removes all session-related data structure in
 * @sessions.
 */
void delete_sessions(struct uftrace_session_link *sessions)
{
	struct uftrace_session *sess;
	struct rb_node *n;

	delete_tasks(sessions);

	while (!RB_EMPTY_ROOT(&sessions->root)) {
		n = rb_first(&sessions->root);
		rb_erase(n, &sessions->root);

		sess = rb_entry(n, struct uftrace_session, node);
		delete_session(sess);
	}
}

static void add_session_ref(struct uftrace_task *task, struct uftrace_session *sess,
			    uint64_t timestamp)
{
	struct uftrace_sess_ref *sref = &task->sref;

	if (sess == NULL) {
		pr_dbg("task %d/%d has no session\n", task->tid, task->pid);
		return;
	}

	if (task->sref_last) {
		task->sref_last->next = sref = xmalloc(sizeof(*sref));
		task->sref_last->end = timestamp;
	}

	sref->next = NULL;
	sref->sess = sess;
	sref->start = timestamp;
	sref->end = -1ULL;

	pr_dbg2("task session: tid = %d, session = %.*s\n", task->tid, SESSION_ID_LEN, sess->sid);
	task->sref_last = sref;
}

/**
 * find_task_session - find a matching session using @pid and @timestamp
 * @sessions: session link to manage sessions and tasks
 * @task: task to search a session
 * @timestamp: timestamp of task
 *
 * This function searches the sessions tree using @task and @timestamp.
 * The most recent session that has a smaller than the @timestamp will
 * be returned.  If it didn't find a session tries to search session
 * list of parent or thread-leader.
 */
struct uftrace_session *find_task_session(struct uftrace_session_link *sessions,
					  struct uftrace_task *task, uint64_t timestamp)
{
	int parent_id;
	struct uftrace_sess_ref *ref;

	while (task != NULL) {
		ref = &task->sref;
		while (ref) {
			if (ref->start <= timestamp && timestamp < ref->end)
				return ref->sess;
			ref = ref->next;
		}

		/*
		 * if it cannot find its own session,
		 * inherit from parent or leader.
		 */
		parent_id = task->ppid ?: task->pid;
		if (parent_id == 0 || parent_id == task->tid)
			break;

		task = find_task(sessions, parent_id);
	}

	return NULL;
}

/**
 * create_task - create a new task from task message
 * @sessions: session link to manage sessions and tasks
 * @msg: ftrace task message read from task file
 * @fork: whether it's forked or not (i.e. thread)
 *
 * This function creates a new task from @msg and add it to task tree.
 * The newly created task will have a reference to a session if
 * @needs_session is %true.
 */
void create_task(struct uftrace_session_link *sessions, struct uftrace_msg_task *msg, bool fork)
{
	struct uftrace_task *t;
	struct uftrace_task *pt;
	struct uftrace_session *s;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions->tasks.rb_node;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct uftrace_task, node);

		if (t->tid > msg->tid)
			p = &parent->rb_left;
		else if (t->tid < msg->tid)
			p = &parent->rb_right;
		else {
			/* add new session */
			s = find_session(sessions, msg->pid, msg->time);
			if (s != NULL)
				add_session_ref(t, s, msg->time);
			return;
		}
	}

	t = xzalloc(sizeof(*t));

	/* msg->pid is a parent pid if forked */
	t->pid = fork ? msg->tid : msg->pid;
	t->tid = msg->tid;
	t->ppid = fork ? msg->pid : 0;
	t->time.stamp = msg->time;

	INIT_LIST_HEAD(&t->children);
	INIT_LIST_HEAD(&t->siblings);

	pt = find_task(sessions, msg->pid);
	if (pt != NULL)
		list_add_tail(&t->siblings, &pt->children);

	s = find_session(sessions, msg->pid, msg->time);
	if (s == NULL) {
		if (pt && pt->sref_last && pt->sref_last->start < msg->time)
			s = pt->sref_last->sess;
	}

	if (s != NULL) {
		add_session_ref(t, s, msg->time);
		strncpy(t->comm, uftrace_basename(s->exename), sizeof(t->comm));
		t->comm[sizeof(t->comm) - 1] = '\0';
	}

	pr_dbg2("new task: tid = %d (%.*s), session = %-.*s\n", t->tid, sizeof(t->comm),
		s ? t->comm : "unknown", SESSION_ID_LEN, s ? s->sid : "unknown");

	if (sessions->first_task == NULL)
		sessions->first_task = t;

	rb_link_node(&t->node, parent, p);
	rb_insert_color(&t->node, &sessions->tasks);
}

static void delete_task(struct uftrace_task *t)
{
	struct uftrace_sess_ref *sref, *tmp;

	sref = t->sref.next;
	while (sref) {
		tmp = sref->next;
		free(sref);
		sref = tmp;
	}
	free(t);
}

static void delete_tasks(struct uftrace_session_link *sessions)
{
	struct uftrace_task *t;
	struct rb_node *n;

	while (!RB_EMPTY_ROOT(&sessions->tasks)) {
		n = rb_first(&sessions->tasks);
		rb_erase(n, &sessions->tasks);

		t = rb_entry(n, struct uftrace_task, node);
		delete_task(t);
	}
}

/**
 * find_task - find a matching task by @tid
 * @sessions: session link to manage sessions and tasks
 * @tid: task id
 */
struct uftrace_task *find_task(struct uftrace_session_link *sessions, int tid)
{
	struct uftrace_task *t;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions->tasks.rb_node;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct uftrace_task, node);

		if (t->tid > tid)
			p = &parent->rb_left;
		else if (t->tid < tid)
			p = &parent->rb_right;
		else
			return t;
	}

	return NULL;
}

/**
 * walk_tasks - iterates all tasks and invokes @callback
 * @sess: session link to manage sessions and tasks
 * @callback: function to be called for each task
 * @arg: argument passed to the @callback
 *
 * This function traverses the task tree and invokes @callback with
 * @arg.  As the @callback returns a non-zero value, it'll stop and
 * return in the middle.
 */
void walk_tasks(struct uftrace_session_link *sessions, walk_tasks_cb_t callback, void *arg)
{
	struct rb_node *n = rb_first(&sessions->tasks);
	struct uftrace_task *t;

	while (n) {
		t = rb_entry(n, struct uftrace_task, node);

		if (callback(t, arg) != 0)
			break;

		n = rb_next(n);
	}
}

/**
 * task_find_sym - find a symbol that matches to @rec
 * @sessions: session link to manage sessions and tasks
 * @task: handle for functions in a task
 * @rec: uftrace data record
 *
 * This function looks up symbol table in current session.
 */
struct uftrace_symbol *task_find_sym(struct uftrace_session_link *sessions,
				     struct uftrace_task_reader *task, struct uftrace_record *rec)
{
	struct uftrace_session *sess;
	struct uftrace_sym_info *sinfo;
	struct uftrace_symbol *sym = NULL;
	uint64_t addr = rec->addr;

	sess = find_task_session(sessions, task->t, rec->time);

	if (is_kernel_record(task, rec)) {
		if (sess == NULL)
			sess = sessions->first;
		addr = get_kernel_address(&sess->sym_info, addr);
	}

	if (sess == NULL)
		return NULL;

	sinfo = &sess->sym_info;
	sym = find_symtabs(sinfo, addr);

	if (sym == NULL)
		sym = session_find_dlsym(sess, rec->time, addr);

	return sym;
}

/**
 * task_find_sym_addr - find a symbol that matches to @addr
 * @sessions: session link to manage sessions and tasks
 * @task: handle for functions in a task
 * @time: timestamp of the @addr
 * @addr: instruction address
 *
 * This function looks up symbol table in current session.
 */
struct uftrace_symbol *task_find_sym_addr(struct uftrace_session_link *sessions,
					  struct uftrace_task_reader *task, uint64_t time,
					  uint64_t addr)
{
	struct uftrace_session *sess;
	struct uftrace_symbol *sym = NULL;

	sess = find_task_session(sessions, task->t, time);

	if (sess == NULL) {
		struct uftrace_session *fsess = sessions->first;

		if (is_kernel_address(&fsess->sym_info, addr))
			sess = fsess;
		else
			return NULL;
	}

	sym = find_symtabs(&sess->sym_info, addr);
	if (sym == NULL)
		sym = session_find_dlsym(sess, time, addr);

	if (sym == NULL) {
		if (EVENT_ID_PERF_SCHED_IN == addr || EVENT_ID_PERF_SCHED_OUT == addr ||
		    EVENT_ID_PERF_SCHED_BOTH == addr)
			return &sched_sym;
		else if (EVENT_ID_PERF_SCHED_OUT_PREEMPT == addr ||
			 EVENT_ID_PERF_SCHED_BOTH_PREEMPT == addr)
			return &sched_preempt_sym;
	}

	return sym;
}

/**
 * task_find_loc_addr - find a debug location that matches to @addr
 * @sessions: session link to manage sessions and tasks
 * @task: handle for functions in a task
 * @time: timestamp of the @addr
 * @addr: instruction address
 *
 * This function returns a debug location of symbol
 * that looked up in symbol table in current session
 */
struct uftrace_dbg_loc *task_find_loc_addr(struct uftrace_session_link *sessions,
					   struct uftrace_task_reader *task, uint64_t time,
					   uint64_t addr)
{
	struct uftrace_session *sess;
	struct uftrace_symbol *sym;
	struct uftrace_mmap *map;
	struct uftrace_module *mod;
	struct uftrace_dbg_info *dinfo;
	struct uftrace_dbg_loc *loc;
	ptrdiff_t sym_idx;

	sess = find_task_session(sessions, task->t, time);

	if (sess == NULL) {
		struct uftrace_session *fsess = sessions->first;

		if (is_kernel_address(&fsess->sym_info, addr))
			sess = fsess;
		else
			return NULL;
	}

	sym = find_symtabs(&sess->sym_info, addr);
	if (sym == NULL)
		sym = session_find_dlsym(sess, time, addr);

	if (sym == NULL)
		return NULL;

	if (sym->type == ST_LOCAL_FUNC || sym->type == ST_GLOBAL_FUNC) {
		map = find_map(&sess->sym_info, addr);
		if (map) {
			mod = map->mod;
			dinfo = &mod->dinfo;
		}
		else {
			struct uftrace_dlopen_list *udl;

			udl = session_find_dlopen(sess, time, addr);
			if (udl == NULL)
				return NULL;

			mod = udl->mod;
			dinfo = &mod->dinfo;
		}

		if (dinfo == NULL || dinfo->nr_locs_used == 0)
			return NULL;

		sym_idx = sym - mod->symtab.sym;
		loc = &dinfo->locs[sym_idx];
		if (loc->file != NULL)
			return loc;
	}

	return NULL;
}

void session_setup_dlopen_argspec(struct uftrace_session *sess,
				  struct uftrace_filter_setting *setting, bool is_retval)
{
	struct uftrace_dlopen_list *udl;

	list_for_each_entry(udl, &sess->dlopen_libs, list) {
		struct uftrace_sym_info dl_info;
		struct uftrace_mmap dl_map = {
			.start = udl->base,
			.mod = udl->mod,
		};

		dl_info = sess->sym_info;
		dl_info.maps = &dl_map;

		if (is_retval) {
			uftrace_setup_retval(setting->info_str, &dl_info, &udl->filter_info,
					     setting);
		}
		else {
			uftrace_setup_argument(setting->info_str, &dl_info, &udl->filter_info,
					       setting);
		}
	}
}

struct uftrace_filter *session_find_filter(struct uftrace_session *sess, struct uftrace_record *rec,
					   struct uftrace_trigger *tr)
{
	struct uftrace_filter *ret;
	struct uftrace_dlopen_list *udl;

	ret = uftrace_match_filter(rec->addr, &sess->filter_info, tr);
	if (ret)
		return ret;

	udl = session_find_dlopen(sess, rec->time, rec->addr);
	if (udl == NULL)
		return NULL;

	return uftrace_match_filter(rec->addr, &udl->filter_info, tr);
}

#ifdef UNIT_TEST

static struct uftrace_session_link test_sessions;
static const char session_map[] = "00400000-00401000 r-xp 00000000 08:03 4096 unittest\n"
				  "bfff0000-bffff000 rw-p 00000000 08:03 4096 [stack]\n";
static const char session_map_with_build_id[] =
	"00400000-00401000 r-xp 00000000 08:03 4096 unittest build-id:1234567890abcdef\n"
	"5f98a000-5fa8c000 r-xp 00000000 08:03 4096 libc.so\n"
	"bfff0000-bffff000 rw-p 00000000 08:03 4096 [stack]\n";

TEST_CASE(session_search)
{
	int i;
	const int NUM_TEST = 100;

	TEST_EQ(test_sessions.first, NULL);

	pr_dbg("create same session %d times\n", NUM_TEST);
	for (i = 0; i < NUM_TEST; i++) {
		struct uftrace_msg_sess msg = {
			.task = {
				.pid = 1,
				.tid = 1,
				.time = i * 100,
			},
			.sid = "test",
			.namelen = 8,  /* = strlen("unittest") */
		};
		int fd;

		fd = creat("sid-test.map", 0400);
		write_all(fd, session_map, sizeof(session_map) - 1);
		close(fd);
		create_session(&test_sessions, &msg, ".", ".", "unittest", false, false, false);
		remove("sid-test.map");
	}

	TEST_NE(test_sessions.first, NULL);
	TEST_EQ(test_sessions.first->pid, 1);
	TEST_EQ(test_sessions.first->start_time, 0);

	pr_dbg("find sessions including random timestamp\n");
	for (i = 0; i < NUM_TEST; i++) {
		int t;
		struct uftrace_session *s;

		t = random() % (NUM_TEST * 100);
		s = find_session(&test_sessions, 1, t);

		TEST_NE(s, NULL);
		TEST_EQ(s->pid, 1);
		TEST_GE(t, s->start_time);
		TEST_LT(t, s->start_time + 100);
	}

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);

	return TEST_OK;
}

TEST_CASE(task_search)
{
	struct uftrace_task *task;
	struct uftrace_session *sess;
	int fd;

	pr_dbg("create initial task\n");
	{
		struct uftrace_msg_sess smsg = {
			.task = {
				.pid = 1,
				.tid = 1,
				.time = 100,
			},
			.sid = "initial",
			.namelen = 8,  /* = strlen("unittest") */
		};
		struct uftrace_msg_task tmsg = {
			.pid = 1,
			.tid = 1,
			.time = 100,
		};

		fd = creat("sid-initial.map", 0400);
		write_all(fd, session_map, sizeof(session_map) - 1);
		close(fd);
		create_session(&test_sessions, &smsg, ".", ".", "unittest", false, false, false);
		create_task(&test_sessions, &tmsg, false);
		remove("sid-initial.map");

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sref.sess, test_sessions.first);
		TEST_NE(test_sessions.first, NULL);

		sess = find_session(&test_sessions, tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, task->pid);
		TEST_EQ(sess->tid, task->tid);
	}

	pr_dbg("fork child task\n");
	{
		struct uftrace_msg_task tmsg = {
			.pid = 1, /* ppid */
			.tid = 2, /* pid */
			.time = 200,
		};

		create_task(&test_sessions, &tmsg, true);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sref.sess, test_sessions.first);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	pr_dbg("create parent thread\n");
	{
		struct uftrace_msg_task tmsg = {
			.pid = 1,
			.tid = 3,
			.time = 300,
		};

		create_task(&test_sessions, &tmsg, false);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sref.sess, test_sessions.first);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	pr_dbg("create child thread\n");
	{
		struct uftrace_msg_task tmsg = {
			.pid = 2,
			.tid = 4,
			.time = 400,
		};

		create_task(&test_sessions, &tmsg, false);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sref.sess, test_sessions.first);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		/* it returned a session from parent so pid is not same */
		TEST_NE(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	pr_dbg("exec from child\n");
	{
		struct uftrace_msg_sess smsg = {
			.task = {
				.pid = 2,
				.tid = 4,
				.time = 500,
			},
			.sid = "after_exec",
			.namelen = 8,  /* = strlen("unittest") */
		};
		struct uftrace_msg_task tmsg = {
			.pid = 2,
			.tid = 4,
			.time = 500,
		};

		fd = creat("sid-after_exec.map", 0400);
		write_all(fd, session_map, sizeof(session_map) - 1);
		close(fd);
		create_session(&test_sessions, &smsg, ".", ".", "unittest", false, false, false);
		create_task(&test_sessions, &tmsg, false);
		remove("sid-after_exec.map");

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, task->pid);
		TEST_EQ(sess->tid, task->tid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	pr_dbg("fork grand-child task\n");
	{
		struct uftrace_msg_task tmsg = {
			.pid = 4, /* ppid */
			.tid = 5, /* pid */
			.time = 600,
		};

		create_task(&test_sessions, &tmsg, true);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->tid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	pr_dbg("create grand-child thread\n");
	{
		struct uftrace_msg_task tmsg = {
			.pid = 5,
			.tid = 6,
			.time = 700,
		};

		create_task(&test_sessions, &tmsg, false);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		/* it returned a session from parent so pid is not same */
		TEST_NE(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	pr_dbg("finding tasks in the initial session\n");
	task = find_task(&test_sessions, 1);
	sess = find_task_session(&test_sessions, task, 100);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	task = find_task(&test_sessions, 2);
	sess = find_task_session(&test_sessions, task, 200);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	task = find_task(&test_sessions, 4);
	sess = find_task_session(&test_sessions, task, 400);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	pr_dbg("finding tasks in the session after exec\n");
	sess = find_task_session(&test_sessions, task, 500);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	task = find_task(&test_sessions, 5);
	sess = find_task_session(&test_sessions, task, 600);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	task = find_task(&test_sessions, 6);
	sess = find_task_session(&test_sessions, task, 700);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.tasks), true);

	return TEST_OK;
}

TEST_CASE(task_symbol)
{
	struct uftrace_symbol *sym;
	struct uftrace_msg_sess msg = {
		.task = {
			.pid = 1,
			.tid = 1,
			.time = 100,
		},
		.sid = "test",
		.namelen = 8,  /* = strlen("unittest") */
	};
	struct uftrace_msg_task tmsg = {
		.pid = 1,
		.tid = 1,
		.time = 100,
	};
	struct uftrace_task_reader task = {
		.tid = 1,
	};
	FILE *fp;

	pr_dbg("creating symbol and map files\n");
	fp = fopen("sid-test.map", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "%s", session_map);
	fclose(fp);

	fp = fopen("unittest.sym", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "00000100 P printf\n");
	fprintf(fp, "00000200 P __dynsym_end\n");
	fprintf(fp, "00000300 T _start\n");
	fprintf(fp, "00000400 T main\n");
	fprintf(fp, "00000500 T __sym_end\n");
	fclose(fp);

	create_session(&test_sessions, &msg, ".", ".", "unittest", false, true, false);
	create_task(&test_sessions, &tmsg, false);
	remove("sid-test.map");
	remove("unittest.sym");

	TEST_NE(test_sessions.first, NULL);
	TEST_EQ(test_sessions.first->pid, 1);

	pr_dbg("try to find a symbol from a mapped address\n");
	task.t = find_task(&test_sessions, 1);
	sym = task_find_sym_addr(&test_sessions, &task, 100, 0x400410);

	TEST_NE(sym, NULL);
	TEST_STREQ(sym->name, "main");

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);

	return TEST_OK;
}

TEST_CASE(task_symbol_dlopen)
{
	struct uftrace_symbol *sym;
	struct uftrace_msg_sess msg = {
		.task = {
			.pid = 1,
			.tid = 1,
			.time = 100,
		},
		.sid = "test",
		.namelen = 8,  /* = strlen("unittest") */
	};
	FILE *fp;

	fp = fopen("sid-test.map", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "%s", session_map);
	fclose(fp);

	pr_dbg("creating symbol for the dlopen library\n");
	fp = fopen("libuftrace-test.so.0.sym", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "0100 P __tls_get_addr\n");
	fprintf(fp, "0200 P __dynsym_end\n");
	fprintf(fp, "0300 T _start\n");
	fprintf(fp, "0400 T foo\n");
	fprintf(fp, "0500 T __sym_end\n");
	fclose(fp);

	create_session(&test_sessions, &msg, ".", ".", "unittest", false, true, false);
	remove("sid-test.map");

	TEST_NE(test_sessions.first, NULL);
	TEST_EQ(test_sessions.first->pid, 1);

	pr_dbg("add dlopen info message\n");
	session_add_dlopen(test_sessions.first, 200, 0x7003000, "libuftrace-test.so.0", false);
	remove("libuftrace-test.so.0.sym");

	TEST_EQ(list_empty(&test_sessions.first->dlopen_libs), false);

	pr_dbg("try to find a symbol from the dlopen address\n");
	sym = session_find_dlsym(test_sessions.first, 250, 0x7003410);

	TEST_NE(sym, NULL);
	TEST_STREQ(sym->name, "foo");

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);

	return TEST_OK;
}

TEST_CASE(session_map_build_id)
{
	FILE *fp;
	struct uftrace_mmap *map;
	struct uftrace_sym_info test_sinfo = {
		.loaded = false,
	};

	fp = fopen("sid-test.map", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "%s", session_map_with_build_id);
	fclose(fp);

	pr_dbg("read map file with build-id info\n");
	read_session_map(".", &test_sinfo, "test");

	pr_dbg("first entry should have a build-id\n");
	map = test_sinfo.maps;
	TEST_NE(map, NULL);
	TEST_STREQ(map->libname, "unittest");
	TEST_STREQ(map->build_id, "1234567890abcdef");

	pr_dbg("next entry should not have one\n");
	map = map->next;
	TEST_NE(map, NULL);
	TEST_STREQ(map->libname, "libc.so");
	TEST_STREQ(map->build_id, "");

	map = map->next;
	TEST_EQ(map, NULL);

	delete_session_map(&test_sinfo);
	return TEST_OK;
}

TEST_CASE(session_autoarg_dlopen)
{
	struct uftrace_session *sess;
	struct uftrace_filter *filter;
	struct uftrace_trigger tr = {};
	struct uftrace_record rec = {
		.time = 234,
		.addr = 0x7003456,
	};
	struct uftrace_msg_sess msg = {
		.task = {
			.pid = 1,
			.tid = 1,
			.time = 100,
		},
		.sid = "test",
		.namelen = 8,  /* = strlen("unittest") */
	};
	struct uftrace_filter_setting setting = {
		.ptype = PATT_SIMPLE,
		.info_str = "foo@auto-args",
	};
	struct uftrace_dlopen_list *udl;
	FILE *fp;

	fp = fopen("sid-test.map", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "%s", session_map);
	fclose(fp);

	pr_dbg("creating symbol for the dlopen library\n");
	fp = fopen("libuftrace-test.so.0.sym", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "0100 P __tls_get_addr\n");
	fprintf(fp, "0200 P __dynsym_end\n");
	fprintf(fp, "0300 T _start\n");
	fprintf(fp, "0400 T foo\n");
	fprintf(fp, "0500 T __sym_end\n");
	fclose(fp);

	pr_dbg("creating debug info for the dlopen library\n");
	fp = fopen("libuftrace-test.so.0.dbg", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "# path name: libuftrace-test.so.0\n");
	fprintf(fp, "# build-id: \n");
	fprintf(fp, "F: 400 foo\n");
	fprintf(fp, "L: 5 s-uftrace-test.c\n");
	fprintf(fp, "A: @arg1,arg2/f32\n");
	fprintf(fp, "R: @retval\n");
	fclose(fp);

	create_session(&test_sessions, &msg, ".", ".", "unittest", false, true, true);
	remove("sid-test.map");

	sess = test_sessions.first;
	TEST_NE(sess, NULL);
	TEST_EQ(sess->pid, 1);

	pr_dbg("add dlopen info message\n");
	session_add_dlopen(sess, 200, 0x7003000, "libuftrace-test.so.0", false);
	remove("libuftrace-test.so.0.sym");
	remove("libuftrace-test.so.0.dbg");

	pr_dbg("set filters for dlopen library\n");
	udl = session_find_dlopen(sess, rec.time, rec.addr);
	TEST_NE(udl, NULL);
	TEST_NE(udl->mod, NULL);

	session_setup_dlopen_argspec(sess, &setting, false);
	session_setup_dlopen_argspec(sess, &setting, true);

#ifdef HAVE_LIBDW
	pr_dbg("try to find a filter for the dlopen address\n");
	filter = session_find_filter(sess, &rec, &tr);

	TEST_NE(filter, NULL);
	TEST_EQ(filter->trigger.flags, TRIGGER_FL_ARGUMENT | TRIGGER_FL_RETVAL);
	TEST_NE(filter->trigger.pargs, NULL);
	TEST_STREQ(filter->name, "foo");
#endif /* HAVE_LIBDW */

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);

	return TEST_OK;
}

#endif /* UNIT_TEST */
