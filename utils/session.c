#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define PR_FMT     "session"
#define PR_DOMAIN  DBG_SESSION

#include "uftrace.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/utils.h"
#include "libmcount/mcount.h"


static struct rb_root sessions = RB_ROOT;

struct ftrace_session *first_session;

static void read_map_file(char *dirname, struct ftrace_session *sess)
{
	FILE *fp;
	char buf[PATH_MAX];
	char *last_libname = NULL;
	struct ftrace_proc_maps **maps = &sess->symtabs.maps;

	snprintf(buf, sizeof(buf), "%s/sid-%.16s.map", dirname, sess->sid);
	fp = fopen(buf, "rb");
	if (fp == NULL)
		pr_err("cannot open maps file: %s", buf);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		unsigned long start, end;
		char prot[5];
		char path[PATH_MAX];
		size_t namelen;
		struct ftrace_proc_maps *map;

		/* skip anon mappings */
		if (sscanf(buf, "%lx-%lx %s %*x %*x:%*x %*d %s\n",
			   &start, &end, prot, path) != 4)
			continue;

		/* skip non-executable mappings */
		if (prot[2] != 'x')
			continue;

		/* use first mapping only */
		if (last_libname && !strcmp(last_libname, path))
			continue;

		namelen = ALIGN(strlen(path) + 1, 4);

		map = xmalloc(sizeof(*map) + namelen);

		map->start = start;
		map->end = end;
		map->len = namelen;
		memcpy(map->prot, prot, 4);
		memcpy(map->libname, path, namelen);
		map->libname[strlen(path)] = '\0';
		last_libname = map->libname;

		map->next = *maps;
		*maps = map;
	}
	fclose(fp);
}

/**
 * create_session - create a new task session from session message
 * @msg: ftrace session message read from task file
 * @dirname: ftrace data directory name
 * @exename: executable name started this session
 *
 * This function allocates a new session started by a task.  The new
 * session will be added to sessions tree sorted by pid and timestamp.
 */
void create_session(struct ftrace_msg_sess *msg, char *dirname, char *exename,
		    bool sym_rel_addr)
{
	struct ftrace_session *s;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions.rb_node;

	while (*p) {
		parent = *p;
		s = rb_entry(parent, struct ftrace_session, node);

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
	s->filters = RB_ROOT;

	pr_dbg2("new session: pid = %d, session = %.16s\n",
		s->pid, s->sid);

	s->symtabs.flags = SYMTAB_FL_USE_SYMFILE | SYMTAB_FL_DEMANGLE;
	if (sym_rel_addr)
		s->symtabs.flags |= SYMTAB_FL_ADJ_OFFSET;

	read_map_file(dirname, s);
	load_symtabs(&s->symtabs, dirname, s->exename);

	if (first_session == NULL)
		first_session = s;

	rb_link_node(&s->node, parent, p);
	rb_insert_color(&s->node, &sessions);
}

/**
 * find_session - find a matching session using @pid and @timestamp
 * @pid: task pid to search
 * @timestamp: timestamp of task
 *
 * This function searches the sessions tree using @pid and @timestamp.
 * The most recent session that has a smaller than the @timestamp will
 * be returned.
 */
struct ftrace_session *find_session(int pid, uint64_t timestamp)
{
	struct ftrace_session *iter;
	struct ftrace_session *s = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions.rb_node;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct ftrace_session, node);

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
 * @callback: function to be called for each task
 * @arg: argument passed to the @callback
 *
 * This function traverses the task tree and invokes @callback with
 * @arg.  As the @callback returns a non-zero value, it'll stop and
 * return in the middle.
 */
void walk_sessions(walk_sessions_cb_t callback, void *arg)
{
	struct rb_node *n = rb_first(&sessions);
	struct ftrace_session *s;

	while (n) {
		s = rb_entry(n, struct ftrace_session, node);

		if (callback(s, arg) != 0)
			break;

		n = rb_next(n);
	}
}

static struct rb_root task_tree = RB_ROOT;

static void add_session_ref(struct ftrace_task *task, struct ftrace_session *sess,
			    uint64_t timestamp)
{
	struct ftrace_sess_ref *ref;

	assert(sess);

	if (task->sess_last) {
		task->sess_last->next = ref = xmalloc(sizeof(*ref));
		task->sess_last->end = timestamp;
	} else
		ref = &task->sess;

	ref->next = NULL;
	ref->sess = sess;
	ref->start = timestamp;
	ref->end = -1ULL;

	pr_dbg2("task session: tid = %d, session = %.16s\n",
		task->tid, sess->sid);
	task->sess_last = ref;
}

/**
 * find_task_session - find a matching session using @pid and @timestamp
 * @pid - task pid to search
 * @timestamp - timestamp of task
 *
 * This function searches the sessions tree using @pid and @timestamp.
 * The most recent session that has a smaller than the @timestamp will
 * be returned.  If it didn't find a session tries to search sesssion
 * list of parent or thread-leader.
 */
struct ftrace_session *find_task_session(int pid, uint64_t timestamp)
{
	struct ftrace_task *t;
	struct ftrace_sess_ref *r;
	struct ftrace_session *s = find_session(pid, timestamp);

	if (s)
		return s;

	/* if it cannot find its own session, inherit from parent or leader */
	t = find_task(pid);
	if (t == NULL)
		return NULL;

	r = &t->sess;
	while (r) {
		if (r->start <= timestamp && timestamp < r->end)
			return r->sess;
		r = r->next;
	}

	return NULL;
}

/**
 * create_task - create a new task from task message
 * @msg: ftrace task message read from task file
 * @fork: whether it's forked or not (i.e. thread)
 * @needs_session: add reference to session of the task
 *
 * This function creates a new task from @msg and add it to task tree.
 * The newly created task will have a reference to a session if
 * @needs_session is %true.
 */
void create_task(struct ftrace_msg_task *msg, bool fork, bool needs_session)
{
	struct ftrace_task *t;
	struct ftrace_session *s;
	struct ftrace_sess_ref *r;
	struct rb_node *parent = NULL;
	struct rb_node **p = &task_tree.rb_node;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct ftrace_task, node);

		if (t->tid > msg->tid)
			p = &parent->rb_left;
		else if (t->tid < msg->tid)
			p = &parent->rb_right;
		else {
			if (needs_session) {
				/* add new session */
				r = xmalloc(sizeof(*r));

				s = find_task_session(msg->pid, msg->time);
				add_session_ref(t, s, msg->time);
			}
			return;
		}
	}

	t = xmalloc(sizeof(*t));

	/* msg->pid is a parent pid if forked */
	t->pid = fork ? msg->tid : msg->pid;
	t->tid = msg->tid;
	t->sess_last = NULL;

	if (needs_session) {
		s = find_task_session(msg->pid, msg->time);
		add_session_ref(t, s, msg->time);

		pr_dbg2("new task: tid = %d, session = %.16s\n", t->tid, s->sid);
	}
	else
		pr_dbg2("new task: tid = %d\n", t->tid);

	rb_link_node(&t->node, parent, p);
	rb_insert_color(&t->node, &task_tree);
}

/**
 * find_task - find a matching task by @tid
 * @tid: task id
 */
struct ftrace_task *find_task(int tid)
{
	struct ftrace_task *t;
	struct rb_node *parent = NULL;
	struct rb_node **p = &task_tree.rb_node;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct ftrace_task, node);

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
 * @callback: function to be called for each task
 * @arg: argument passed to the @callback
 *
 * This function traverses the task tree and invokes @callback with
 * @arg.  As the @callback returns a non-zero value, it'll stop and
 * return in the middle.
 */
void walk_tasks(walk_tasks_cb_t callback, void *arg)
{
	struct rb_node *n = rb_first(&task_tree);
	struct ftrace_task *t;

	while (n) {
		t = rb_entry(n, struct ftrace_task, node);

		if (callback(t, arg) != 0)
			break;

		n = rb_next(n);
	}
}

#ifdef UNIT_TEST

TEST_CASE(session_search)
{
	int i;

	TEST_EQ(first_session, NULL);

	for (i = 0; i < 1000; i++) {
		struct ftrace_msg_sess msg = {
			.task = {
				.pid = 1,
				.tid = 1,
				.time = i * 100,
			},
			.sid = "test",
			.namelen = 8,  /* = strlen("unittest") */
		};

		creat("sid-test.map", 0400);
		create_session(&msg, ".", "unittest", false);
		remove("sid-test.map");
	}

	TEST_NE(first_session, NULL);
	TEST_EQ(first_session->pid, 1);
	TEST_EQ(first_session->start_time, 0);

	for (i = 0; i < 1000; i++) {
		int t;
		struct ftrace_session *s;

		t = random() % (1000 * 100);
		s = find_session(1, t);

		TEST_NE(s, NULL);
		TEST_EQ(s->pid, 1);
		TEST_GE(t, s->start_time);
		TEST_LT(t, s->start_time + 100);
	}

	return TEST_OK;
}

TEST_CASE(task_search)
{
	struct ftrace_task *task;
	struct ftrace_session *sess;

	/* 1. create initial task */
	{
		struct ftrace_msg_sess smsg = {
			.task = {
				.pid = 1,
				.tid = 1,
				.time = 100,
			},
			.sid = "initial",
			.namelen = 8,  /* = strlen("unittest") */
		};
		struct ftrace_msg_task tmsg = {
			.pid = 1,
			.tid = 1,
			.time = 100,
		};

		creat("sid-initial.map", 0400);
		create_session(&smsg, ".", "unittest", false);
		create_task(&tmsg, false, true);
		remove("sid-initial.map");

		task = find_task(tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sess.sess, first_session);
		TEST_NE(first_session, NULL);

		sess = find_session(tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, task->pid);
		TEST_EQ(sess->tid, task->tid);
	}

	/* 2. fork child task */
	{
		struct ftrace_msg_task tmsg = {
			.pid = 1,  /* ppid */
			.tid = 2,  /* pid */
			.time = 200,
		};

		create_task(&tmsg, true, true);

		task = find_task(tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sess.sess, first_session);

		sess = find_task_session(tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 3. create parent thread */
	{
		struct ftrace_msg_task tmsg = {
			.pid = 1,
			.tid = 3,
			.time = 300,
		};

		create_task(&tmsg, false, true);

		task = find_task(tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sess.sess, first_session);

		sess = find_task_session(tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 4. create child thread */
	{
		struct ftrace_msg_task tmsg = {
			.pid = 2,
			.tid = 4,
			.time = 400,
		};

		create_task(&tmsg, false, true);

		task = find_task(tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sess.sess, first_session);

		sess = find_task_session(tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		/* it returned a session from parent so pid is not same */
		TEST_NE(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 5. exec from child */
	{
		struct ftrace_msg_sess smsg = {
			.task = {
				.pid = 2,
				.tid = 4,
				.time = 500,
			},
			.sid = "after_exec",
			.namelen = 8,  /* = strlen("unittest") */
		};
		struct ftrace_msg_task tmsg = {
			.pid = 2,
			.tid = 4,
			.time = 500,
		};

		creat("sid-after_exec.map", 0400);
		create_session(&smsg, ".", "unittest", false);
		create_task(&tmsg, false, true);
		remove("sid-after_exec.map");

		task = find_task(tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, task->pid);
		TEST_EQ(sess->tid, task->tid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 6. fork grand-child task */
	{
		struct ftrace_msg_task tmsg = {
			.pid = 4,  /* ppid */
			.tid = 5,  /* pid */
			.time = 600,
		};

		create_task(&tmsg, true, true);

		task = find_task(tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->tid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 7. create grand-child thread */
	{
		struct ftrace_msg_task tmsg = {
			.pid = 5,
			.tid = 6,
			.time = 700,
		};

		create_task(&tmsg, false, true);

		task = find_task(tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		/* it returned a session from parent so pid is not same */
		TEST_NE(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	sess = find_task_session(1, 100);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	sess = find_task_session(2, 200);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	sess = find_task_session(4, 400);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	sess = find_task_session(4, 500);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	sess = find_task_session(5, 600);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	sess = find_task_session(6, 700);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	sess = find_task_session(6, 100);
	TEST_EQ(sess, NULL);

	return TEST_OK;
}

#endif /* UNIT_TEST */
