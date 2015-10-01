#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "../ftrace.h"
#include "../libmcount/mcount.h"
#include "symbol.h"
#include "rbtree.h"
#include "utils.h"


static struct rb_root sessions = RB_ROOT;

struct ftrace_session *first_session;

void create_session(struct ftrace_msg_sess *msg, char *dirname, char *exename)
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

	load_symtabs(&s->symtabs, dirname, s->exename);

	if (first_session == NULL)
		first_session = s;

	rb_link_node(&s->node, parent, p);
	rb_insert_color(&s->node, &sessions);
}

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

	task->sess_last = ref;
}

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

void create_task(struct ftrace_msg_task *msg, bool fork)
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
			/* add new session */
			r = xmalloc(sizeof(*r));

			s = find_task_session(msg->pid, msg->time);
			add_session_ref(t, s, msg->time);

			pr_dbg("new session: tid = %d, session = %.16s\n",
			       t->tid, s->sid);
			return;
		}
	}

	t = xmalloc(sizeof(*t));

	t->pid = fork ? msg->tid : msg->pid;
	t->tid = msg->tid;
	t->sess_last = NULL;

	s = find_task_session(msg->pid, msg->time);
	add_session_ref(t, s, msg->time);

	pr_dbg("new task: tid = %d, session = %.16s\n", t->tid, s->sid);

	rb_link_node(&t->node, parent, p);
	rb_insert_color(&t->node, &task_tree);
}

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
