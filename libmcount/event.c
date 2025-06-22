#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "event"
#define PR_DOMAIN DBG_EVENT

#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "utils/filter.h"
#include "utils/list.h"
#include "utils/utils.h"

#define SDT_SECT ".note.stapsdt"
#define SDT_NAME "stapsdt"
#define SDT_TYPE 3

/* systemtap SDT data structure */
struct stapsdt {
	unsigned long probe_addr;
	unsigned long link_addr;
	unsigned long sema_addr;
	char vea[]; /* vendor + event + arguments */
};

/* user-given event specifier (may contains patterns) */
struct event_spec {
	struct list_head list;
	struct uftrace_pattern provider;
	struct uftrace_pattern event;
};

/* list of event spec */
static LIST_HEAD(events);

/* event id which is allocated dynamically */
static unsigned event_id = EVENT_ID_USER;

static int search_sdt_event(struct dl_phdr_info *info, size_t sz, void *data)
{
	const char *name = info->dlpi_name;
	struct mcount_event_info *mei;
	struct list_head *spec_list = data;
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	bool found_sdt = false;
	int ret = -1;

	if (name[0] == '\0')
		name = read_exename();

	if (elf_init(name, &elf) < 0) {
		pr_dbg("error during open file: %s: %m\n", name);
		return -1;
	}

	elf_for_each_shdr(&elf, &iter) {
		char *shstr;

		if (iter.shdr.sh_type != SHT_NOTE)
			continue;

		/* there can be more than one note sections */
		shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (strcmp(shstr, SDT_SECT) == 0) {
			found_sdt = true;
			break;
		}
	}

	if (!found_sdt) {
		ret = 0;
		goto out;
	}

	pr_dbg2("loading sdt notes from %s\n", name);

	elf_for_each_note(&elf, &iter) {
		struct stapsdt *sdt;
		struct event_spec *spec;
		char *vendor, *event, *args;

		if (strncmp(iter.note_name, SDT_NAME, iter.nhdr.n_namesz))
			continue;

		if (iter.nhdr.n_type != SDT_TYPE)
			continue;

		sdt = iter.note_desc;

		vendor = sdt->vea;
		event = vendor + strlen(vendor) + 1;
		args = event + strlen(event) + 1;

		if (list_empty(spec_list)) {
			/* just listing available events */
			pr_out("[SDT event] %s:%s %s\n", vendor, event, args);
			continue;
		}

		list_for_each_entry(spec, spec_list, list) {
			if (!match_filter_pattern(&spec->provider, vendor))
				continue;
			if (!match_filter_pattern(&spec->event, event))
				continue;
			break;
		}
		if (list_no_entry(spec, spec_list, list))
			continue;

		mei = xmalloc(sizeof(*mei));
		mei->id = event_id++;
		mei->addr = info->dlpi_addr + sdt->probe_addr;
		mei->module = xstrdup(name);
		mei->provider = xstrdup(vendor);
		mei->event = xstrdup(event);
		mei->arguments = xstrdup(args);

		pr_dbg("adding SDT event (%s:%s) from %s at %#lx\n", mei->provider, mei->event,
		       mei->module, mei->addr);

		list_add_tail(&mei->list, &events);
	}

	ret = 0;
out:
	elf_finish(&elf);
	return ret;
}

int mcount_setup_events(char *dirname, char *event_str, enum uftrace_pattern_type ptype)
{
	int ret = 0;
	FILE *fp;
	char *filename = NULL;
	struct mcount_event_info *mei;
	struct strv strv = STRV_INIT;
	LIST_HEAD(specs);
	struct event_spec *es, *tmp;
	char *spec;
	int i;

	strv_split(&strv, event_str, ";");

	strv_for_each(&strv, spec, i) {
		char *sep = strchr(spec, ':');
		char *kernel;

		if (sep) {
			*sep++ = '\0';

			kernel = has_kernel_filter(sep);
			if (kernel)
				continue;

			es = xmalloc(sizeof(*es));

			init_filter_pattern(ptype, &es->provider, spec);
			init_filter_pattern(ptype, &es->event, sep);
			list_add_tail(&es->list, &specs);
		}
		else {
			pr_dbg("ignore invalid event spec: %s\n", spec);
		}
	}

	dl_iterate_phdr(search_sdt_event, &specs);

	list_for_each_entry_safe(es, tmp, &specs, list) {
		list_del(&es->list);

		free_filter_pattern(&es->provider);
		free_filter_pattern(&es->event);
		free(es);
	}
	strv_free(&strv);

	if (list_empty(&events)) {
		pr_dbg("cannot find any event for %s\n", event_str);
		goto out;
	}

	xasprintf(&filename, "%s/events.txt", dirname);

	fp = fopen(filename, "w");
	if (fp == NULL)
		pr_err("cannot open file: %s", filename);

	list_for_each_entry(mei, &events, list) {
		fprintf(fp, "EVENT: %u %s:%s\n", mei->id, mei->provider, mei->event);
	}

	fclose(fp);
	free(filename);

	list_for_each_entry(mei, &events, list) {
		/* ignore failures */
		if (mcount_arch_ops.enable_event)
			mcount_arch_ops.enable_event(mei);
	}
out:
	return ret;
}

struct mcount_event_info *mcount_lookup_event(unsigned long addr)
{
	struct mcount_event_info *mei;

	list_for_each_entry(mei, &events, list) {
		if (mei->addr == addr)
			return mei;
	}
	return NULL;
}

void mcount_list_events(void)
{
	LIST_HEAD(list);

	dl_iterate_phdr(search_sdt_event, &list);
}

/* save an asynchronous event */
int mcount_save_event(struct mcount_event_info *mei)
{
	struct mcount_thread_data *mtdp;

	if (unlikely(mcount_should_stop()))
		return -1;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return -1;

	if (mtdp->nr_events < MAX_EVENT) {
		int i = mtdp->nr_events++;

		mtdp->event[i].id = mei->id;
		mtdp->event[i].time = mcount_gettime();
		mtdp->event[i].dsize = 0;
		mtdp->event[i].idx = ASYNC_IDX;
	}

	return 0;
}

void mcount_finish_events(void)
{
	struct mcount_event_info *mei, *tmp;

	list_for_each_entry_safe(mei, tmp, &events, list) {
		list_del(&mei->list);
		free(mei->module);
		free(mei->provider);
		free(mei->event);
		free(mei->arguments);
		free(mei);
	}
}

#ifdef UNIT_TEST
TEST_CASE(mcount_list_event)
{
	pr_dbg("checking event list\n");
	mcount_list_events();
	TEST_EQ(mcount_lookup_event(0x123), NULL);
	mcount_finish_events();

	return TEST_OK;
}
#endif /* UNIT_TEST */
