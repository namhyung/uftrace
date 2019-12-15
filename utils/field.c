#include "utils/field.h"
#include "utils/fstack.h"
#include "utils/list.h"

void print_header(struct list_head *output_fields, const char *prefix,
		  int space)
{
	struct display_field *field;
	bool first = true;

	/* do not print anything if not needed */
	if (list_empty(output_fields))
		return;

	list_for_each_entry(field, output_fields, list) {
		pr_out("%*s", space, first ? prefix : "");
		pr_out("%s", field->header);
		first = false;
	}

	pr_out("   FUNCTION\n");
}

int print_field_data(struct list_head *output_fields, struct field_data *fd,
		     int space)
{
	struct display_field *field;

	if (list_empty(output_fields))
		return 0;

	list_for_each_entry(field, output_fields, list) {
		pr_out("%*s", space, "");
		field->print(fd);
	}
	return 1;
}

int print_empty_field(struct list_head *output_fields, int space)
{
	struct display_field *field;

	if (list_empty(output_fields))
		return 0;

	list_for_each_entry(field, output_fields, list)
		pr_out("%*s", field->length + space, "");

	return 1;
}

void print_addr(struct field_data *fd)
{
	/* uftrace records (truncated) 48-bit addresses */
	int width = sizeof(long) == 4 ? 8 : 12;

	if (fd->addr == 0)  /* for EVENT or LOST record */
		fd->print("%*s", width, "");
	else
		fd->print("%*lx", width, ADDR_IN_48_BITS(fd->addr));
}

void add_field(struct list_head *output_fields, struct display_field *field)
{
	if (field->used)
		return;

	pr_dbg("add field \"%s\"\n", field->name);

	field->used = true;
	list_add_tail(&field->list, output_fields);
}

static bool check_field_name(struct display_field *field, const char *name)
{
	if (!strcmp(field->name, name))
		return true;

	if (field->alias && !strcmp(field->alias, name))
		return true;

	return false;
}

void setup_field(struct list_head *output_fields, struct opts *opts,
		 void (*setup_default_field)(struct list_head *fields, struct opts*),
		 struct display_field *field_table[], size_t field_table_size)
{
	struct display_field *field;
	struct strv strv = STRV_INIT;
	char *str, *p;
	unsigned i;
	int j;

	/* default fields */
	if (opts->fields == NULL) {
		setup_default_field(output_fields, opts);
		return;
	}

	if (!strcmp(opts->fields, "none"))
		return;

	str = opts->fields;

	if (*str == '+') {
		/* prepend default fields */
		setup_default_field(output_fields, opts);
		str++;
	}

	strv_split(&strv, str, ",");

	strv_for_each(&strv, p, j) {
		for (i = 0; i < field_table_size; i++) {
			field = field_table[i];

			pr_dbg2("check field \"%s\"\n", field->name);
			if (!check_field_name(field, p))
				continue;

			add_field(output_fields, field);
			break;
		}

		if (i == field_table_size) {
			pr_out("uftrace: Unknown field name '%s'\n", p);
			pr_out("uftrace:   Possible fields are:");
			for (i = 0; i < field_table_size; i++)
				pr_out(" %s", field_table[i]->name);
			pr_out("\n");
			exit(1);
		}
	}
	strv_free(&strv);
}
