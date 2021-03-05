#include "utils/field.h"
#include "utils/fstack.h"
#include "utils/list.h"

void print_header(struct list_head *output_fields, const char *prefix,
		  const char *postfix, int space, bool new_line)
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

	pr_out("   %s", postfix);
	if (new_line)
		pr_out("\n");
}

void print_header_align(struct list_head *output_fields, const char *prefix,
			const char *postfix, int space, enum align_pos align,
			bool new_line)
{
	struct display_field *field;
	bool first = true;

	/* do not print anything if not needed */
	if (list_empty(output_fields))
		return;

	list_for_each_entry(field, output_fields, list) {
		pr_out("%*s", space, first ? prefix : "");
		if (align == ALIGN_LEFT)
			pr_out("%-*s", field->length, field->header);
		else
			pr_out("%*s", field->length, field->header);
		first = false;
	}

	pr_out("%*s", space, " ");
	pr_out("%s", postfix);
	if (new_line)
		pr_out("\n");
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
		 setup_default_field_t setup_default_field,
		 struct display_field *field_table[], size_t field_table_size)
{
	struct display_field *field;
	struct strv strv = STRV_INIT;
	char *str, *p;
	unsigned i;
	int j;

	/* default fields */
	if (opts->fields == NULL) {
		setup_default_field(output_fields, opts, field_table);
		return;
	}

	if (!strcmp(opts->fields, "none"))
		return;

	str = opts->fields;

	if (*str == '+') {
		/* prepend default fields */
		setup_default_field(output_fields, opts, field_table);
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

#ifdef UNIT_TEST

static void print_nothing(struct field_data* fd) {}

static void setup_first_field(struct list_head *head, struct opts *opts,
			      struct display_field *p_field_table[])
{
	add_field(head, p_field_table[0]);
}

#define DEFINE_FIELD(_id, _name, _alias)			\
static struct display_field field##_id = {			\
	.id = _id, .name = _name, .header = _name,		\
	.length = 1, .print = print_nothing, .alias = _alias,	\
}

DEFINE_FIELD(1, "foo", "FOO");
DEFINE_FIELD(2, "bar", "baz");
DEFINE_FIELD(3, "abc", "xyz");

static struct display_field *test_field_table[] = {
	&field1, &field2, &field3,
};

TEST_CASE(field_setup_default)
{
	LIST_HEAD(output_fields);
	struct opts opts = { .fields = NULL, };

	pr_dbg("calling setup_default_field\n");
	setup_field(&output_fields, &opts, setup_first_field,
		    test_field_table, ARRAY_SIZE(test_field_table));

	TEST_EQ(output_fields.next, &field1.list);
	TEST_EQ(field1.used, true);
	TEST_EQ(field2.used, false);
	TEST_EQ(field3.used, false);

	return TEST_OK;
}

TEST_CASE(field_setup_default_plus)
{
	LIST_HEAD(output_fields);
	struct opts opts = { .fields = "+abc", };

	pr_dbg("add 'abc' field after the default\n");
	setup_field(&output_fields, &opts, setup_first_field,
		    test_field_table, ARRAY_SIZE(test_field_table));

	TEST_EQ(output_fields.next, &field1.list);
	TEST_EQ(field1.used, true);
	TEST_EQ(field2.used, false);
	TEST_EQ(field3.used, true);

	return TEST_OK;
}

TEST_CASE(field_setup_list)
{
	LIST_HEAD(output_fields);
	struct opts opts = { .fields = "bar,foo", };

	pr_dbg("setup fields in a given order\n");
	setup_field(&output_fields, &opts, setup_first_field,
		    test_field_table, ARRAY_SIZE(test_field_table));

	TEST_EQ(output_fields.next, &field2.list);
	TEST_EQ(field1.used, true);
	TEST_EQ(field2.used, true);
	TEST_EQ(field3.used, false);

	return TEST_OK;
}

TEST_CASE(field_setup_list_alias)
{
	LIST_HEAD(output_fields);
	struct opts opts = { .fields = "baz,xyz", };

	pr_dbg("setup fields with alias name\n");
	setup_field(&output_fields, &opts, setup_first_field,
		    test_field_table, ARRAY_SIZE(test_field_table));

	TEST_EQ(output_fields.next, &field2.list);
	TEST_EQ(field1.used, false);
	TEST_EQ(field2.used, true);
	TEST_EQ(field3.used, true);

	return TEST_OK;
}

#endif  /* UNIT_TEST */
