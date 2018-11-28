/**
 * external data support
 *
 * An external data comes with a text file containing following info:
 *
 *  #        TIMESTAMP MESSAGE
 *  16414531.193431732 this is random text
 *  16414631.732980320 next message
 *  16414706.137491843 3rd message
 *  ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "fstack"
#define PR_DOMAIN  DBG_FSTACK

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"

#define DEFAULT_FILENAME  "extern.dat"

int setup_extern_data(struct uftrace_data *handle, struct opts *opts)
{
	struct uftrace_extern_reader *extn;
	char *filename;
	FILE *fp;

	handle->extn = NULL;

	filename = opts->extern_data;
	if (filename == NULL)
		xasprintf(&filename, "%s/%s", opts->dirname, DEFAULT_FILENAME);

	fp = fopen(filename, "r");

	if (opts->extern_data == NULL)
		free(filename);

	if (fp == NULL) {
		if (errno == ENOENT)
			return 0;

		/* report other error code */
		pr_dbg("opening external data filed: %m\n");
		return -1;
	}

	extn = xzalloc(sizeof(*extn));
	extn->fp = fp;

	handle->extn = extn;
	return 1;
}

int read_extern_data(struct uftrace_extern_reader *extn)
{
	char buf[EXTERN_DATA_MAX + 64];
	char *pos;
	int len;

	if (extn == NULL)
		return -1;

	if (extn->valid)
		return 0;

	do {
		pos = fgets(buf, sizeof(buf), extn->fp);
		if (pos == NULL)
			return -1;  /* end of file */

		buf[sizeof(buf)-1] = '\0';
		while (isspace(*pos))
			pos++;
	}
	while (*pos == '#' || *pos == '\n');  /* ignore comment or blank */

	extn->time = parse_timestamp(pos);

	pos = strpbrk(pos, "\t ");
	if (pos == NULL)
		return -1;  /* invalid data */

	while (isspace(*pos))
		pos++;

	len = strlen(pos);
	if (pos[len-1] == '\n')
		pos[len-1] = '\0';

	strcpy(extn->msg, pos);

	extn->valid = true;
	return 0;
}

struct uftrace_record * get_extern_record(struct uftrace_extern_reader *extn,
					  struct uftrace_record *rec)
{
	rec->time  = extn->time;
	rec->type  = UFTRACE_EVENT;
	rec->addr  = EVENT_ID_EXTERN_DATA;
	rec->more  = 1;
	rec->magic = RECORD_MAGIC;

	return rec;
}

int finish_extern_data(struct uftrace_data *handle)
{
	struct uftrace_extern_reader *extn = handle->extn;

	if (extn && extn->fp != NULL) {
		fclose(extn->fp);
		extn->fp = NULL;

		handle->extn = NULL;
	}
	return 0;
}
