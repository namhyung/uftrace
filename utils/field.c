#include "utils/field.h"
#include "utils/fstack.h"
#include "utils/list.h"

void print_header(struct list_head *output_fields)
{
	struct display_field *field;

	/* do not print anything if not needed */
	if (list_empty(output_fields))
		return;

	pr_out("#");
	list_for_each_entry(field, output_fields, list)
		pr_out("%s ", field->header);

	pr_out("  FUNCTION\n");
}

int print_field_data(struct list_head *output_fields, struct field_data *fd)
{
	struct display_field *field;

	if (list_empty(output_fields))
		return 0;

	pr_out(" ");
	list_for_each_entry(field, output_fields, list) {
		field->print(fd);
		pr_out(" ");
	}
	return 1;
}

int print_empty_field(struct list_head *output_fields)
{
	struct display_field *field;

	if (list_empty(output_fields))
		return 0;

	pr_out(" ");
	list_for_each_entry(field, output_fields, list)
		pr_out("%*s ", field->length, "");
	return 1;
}

void add_field(struct list_head *output_fields, struct display_field *field)
{
	if (field->used)
		return;

	field->used = true;
	list_add_tail(&field->list, output_fields);
}
