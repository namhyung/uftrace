/*
 * Very simple (and incomplete by design) Rust name demangler.
 *
 * Copyright (C) 2026, Namhyung Kim <namhyung@gmail.com>
 *
 * See https://doc.rust-lang.org/rustc/symbol-mangling/v0.html
 */

#include <stdlib.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "demangle"
#define PR_DOMAIN DBG_DEMANGLE

#include <stdlib.h>

#include "utils/demangle.h"
#include "utils/utils.h"

static int dd_rv0_backref(struct demangle_data *dd);
static int dd_rv0_const(struct demangle_data *dd);
static int dd_rv0_lifetime(struct demangle_data *dd);
static int dd_rv0_path(struct demangle_data *dd);
static int dd_rv0_type(struct demangle_data *dd);

static int dd_rv0_base62_num(struct demangle_data *dd, int *num)
{
	int n = 0;

	while (!dd_eof(dd) && dd_curr(dd) != '_') {
		char c = dd_curr(dd);
		int val;

		if (isdigit(c))
			val = c - '0';
		else if (islower(c))
			val = c - 'a' + 10;
		else if (isupper(c))
			val = c - 'A' + 36;
		else
			return -1;

		n *= 62;
		n += val + 1;

		dd->pos++;
	}

	if (dd_eof(dd))
		return -1;

	if (num)
		*num = n;

	dd->pos++;
	return 0;
}

static int dd_rv0_ambiguator(struct demangle_data *dd)
{
	if (dd_curr(dd) != 's')
		return 0;

	DD_DEBUG_CONSUME(dd, 's');
	return dd_rv0_base62_num(dd, NULL);
}

static int dd_rv0_disambig_ident(struct demangle_data *dd)
{
	int n;
	char *p;

	/* optional 'unicode' prefix */
	if (dd_curr(dd) == 'u')
		dd->pos++;

	/* read the name length */
	n = strtol(&dd->old[dd->pos], &p, 0);
	if (n < 0)
		return -1;

	/* update the position after the length */
	dd->pos = p - dd->old;

	/* ignore optional length separator */
	if (dd->old[dd->pos] == '_')
		dd->pos++;

	/* closures may have 0 length */
	if ((dd->type == 0 || dd->type_info) && n > 0 && !dd->ignore_disc) {
		dd_append_separator(dd, "::");
		dd_append_len(dd, &dd->old[dd->pos], n);
	}
	dd->pos += n;
	return 0;
}

/* It doesn't handle unicode (Punicode). */
static int dd_rv0_ident(struct demangle_data *dd)
{
	/* optional disambiguator */
	if (dd_rv0_ambiguator(dd) < 0)
		return -1;

	dd_add_debug(dd);

	return dd_rv0_disambig_ident(dd);
}

static int dd_rv0_array_type(struct demangle_data *dd)
{
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'A');
	dd->level++;

	if (print_type)
		dd_append(dd, "[");

	if (dd_rv0_type(dd) < 0)
		return -1;

	if (print_type)
		dd_append(dd, ";");

	if (dd_rv0_const(dd) < 0)
		return -1;

	if (print_type)
		dd_append(dd, "]");

	dd->level--;
	return 0;
}

static int dd_rv0_slice_type(struct demangle_data *dd)
{
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'S');

	if (print_type)
		dd_append(dd, "[");

	if (dd_rv0_type(dd) < 0)
		return -1;

	if (print_type)
		dd_append(dd, "]");

	return 0;
}

static int dd_rv0_tuple_type(struct demangle_data *dd)
{
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'T');
	dd->level++;

	if (print_type)
		dd_append(dd, "(");

	while (!dd_eof(dd) && dd_curr(dd) != 'E') {
		if (dd_rv0_type(dd) < 0)
			return -1;
		if (print_type)
			dd_append(dd, ",");
	}

	dd->level--;
	__DD_DEBUG_CONSUME(dd, 'E');

	if (print_type) {
		dd->pos--;
		dd_append(dd, ")");
	}

	return 0;
}

static int dd_rv0_ptr_type(struct demangle_data *dd)
{
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'P');

	if (print_type)
		dd_append(dd, "*const_");

	if (dd_rv0_type(dd) < 0)
		return -1;

	return 0;
}

static int dd_rv0_mutptr_type(struct demangle_data *dd)
{
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'O');

	if (print_type)
		dd_append(dd, "*mut_");

	if (dd_rv0_type(dd) < 0)
		return -1;

	return 0;
}

static int dd_rv0_ref_type(struct demangle_data *dd)
{
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'R');

	if (print_type)
		dd_append(dd, "&");

	if (dd_curr(dd) == 'L')
		dd_rv0_lifetime(dd);

	if (dd_rv0_type(dd) < 0)
		return -1;

	return 0;
}

static int dd_rv0_mutref_type(struct demangle_data *dd)
{
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'Q');

	if (print_type)
		dd_append(dd, "&mut_");

	if (dd_curr(dd) == 'L')
		dd_rv0_lifetime(dd);

	if (dd_rv0_type(dd) < 0)
		return -1;

	return 0;
}

static int dd_rv0_binder(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'R');
	return dd_rv0_base62_num(dd, NULL);
}

static int dd_rv0_abi(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'K');

	if (dd_curr(dd) == 'C') {
		dd->pos++; /* "C" ABI */
		return 0;
	}

	return dd_rv0_disambig_ident(dd);
}

static int dd_rv0_fn_type(struct demangle_data *dd)
{
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;
	bool old_ignore_disc = dd->ignore_disc;
	bool has_args = false;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'F');
	dd->level++;

	/* ignore 'unsafe' prefix */
	if (dd_curr(dd) == 'U')
		dd->pos++;

	/* ignore ABI prefix */
	if (dd_curr(dd) == 'K')
		dd_rv0_abi(dd);

	if (print_type)
		dd_append(dd, "fn(");

	while (!dd_eof(dd) && dd_curr(dd) != 'E') {
		if (dd_rv0_type(dd) < 0)
			return -1;

		if (print_type)
			dd_append(dd, ",");

		has_args = true;
	}

	/* remove the last comma */
	if (print_type && has_args)
		dd->newpos--;

	dd->level--;
	__DD_DEBUG_CONSUME(dd, 'E');

	if (print_type)
		dd_append(dd, ")");

	/* do not print the return type */
	dd->ignore_disc = true;
	if (dd_rv0_type(dd) < 0)
		return -1;
	dd->ignore_disc = old_ignore_disc;

	return 0;
}

static int dd_rv0_pattern_kind(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	if (dd_curr(dd) == 'R') {
		/* range pattern kind */
		if (dd_rv0_const(dd) < 0)
			return -1;
		if (dd_rv0_const(dd) < 0)
			return -1;
	}
	else if (dd_curr(dd) == 'O') {
		/* OR pattern kind */
		while (!dd_eof(dd) && dd_curr(dd) != 'E') {
			if (dd_rv0_pattern_kind(dd) < 0)
				return -1;
		}
		if (dd_eof(dd))
			return -1;
		/* consume the last 'E' */
		dd->pos++;
	}

	return 0;
}

static int dd_rv0_pattern_type(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'W');
	dd->level++;

	if (dd_rv0_pattern_kind(dd) < 0)
		return -1;

	dd->level--;
	return 0;
}

static int dd_rv0_dyn_trait_assoc_binding(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	if (dd_curr(dd) != 'p')
		DD_DEBUG(dd, "dyn trait associated binding", 0);

	dd->pos++;

	if (dd_rv0_disambig_ident(dd) < 0)
		return -1;

	return dd_rv0_type(dd);
}

static int dd_rv0_dyn_trait(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	if (dd_rv0_path(dd) < 0)
		return -1;

	while (!dd_eof(dd) && dd_curr(dd) != 'p') {
		if (dd_rv0_dyn_trait_assoc_binding(dd) < 0)
			return -1;
	}

	return 0;
}

static int dd_rv0_dyn_type(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'D');
	dd->level++;

	/* optional binder */
	if (dd_curr(dd) == 'G')
		dd_rv0_binder(dd);

	while (!dd_eof(dd) && dd_curr(dd) != 'E') {
		if (dd_rv0_dyn_trait(dd) < 0)
			return -1;
	}

	dd->level--;
	__DD_DEBUG_CONSUME(dd, 'E');

	return dd_rv0_lifetime(dd);
}

static int dd_rv0_type(struct demangle_data *dd)
{
	static const struct {
		char sig;
		const char *name;
	} builtins[] = {
		{ 'a', "i8" },	{ 'b', "bool" }, { 'c', "char" },  { 'd', "f64" },   { 'e', "str" },
		{ 'f', "f32" }, { 'h', "u8" },	 { 'i', "isize" }, { 'j', "usize" }, { 'l', "i32" },
		{ 'm', "u32" }, { 'n', "i128" }, { 'o', "u128" },  { 's', "i16" },   { 't', "u16" },
		{ 'u', "()" },	{ 'v', "..." },	 { 'x', "i64" },   { 'y', "u64" },   { 'z', "!" },
		{ 'p', "_" },
	};
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;
	char c = dd_curr(dd);
	int ret;

	dd->type++;

	if (islower(c)) {
		for (unsigned k = 0; k < ARRAY_SIZE(builtins); k++) {
			if (builtins[k].sig == c) {
				if (print_type)
					dd_append(dd, builtins[k].name);
				dd->pos++;
				dd->type--;
				return 0;
			}
		}
		DD_DEBUG(dd, "builtin type", 0);
	}

	switch (c) {
	case 'A': /* array */
		ret = dd_rv0_array_type(dd);
		break;
	case 'D': /* dynamic trait */
		ret = dd_rv0_dyn_type(dd);
		break;
	case 'F': /* function pointer */
		ret = dd_rv0_fn_type(dd);
		break;
	case 'O': /* mutable pointer */
		ret = dd_rv0_mutptr_type(dd);
		break;
	case 'P': /* (const) pointer */
		ret = dd_rv0_ptr_type(dd);
		break;
	case 'Q': /* reference */
		ret = dd_rv0_mutref_type(dd);
		break;
	case 'R': /* mutable reference */
		ret = dd_rv0_ref_type(dd);
		break;
	case 'S': /* slice */
		ret = dd_rv0_slice_type(dd);
		break;
	case 'T': /* tuple */
		ret = dd_rv0_tuple_type(dd);
		break;
	case 'W': /* patterns */
		ret = dd_rv0_pattern_type(dd);
		break;
	default:
		ret = dd_rv0_path(dd);
		break;
	}

	dd->type--;
	return ret;
}

static int dd_rv0_impl_path(struct demangle_data *dd)
{
	/* optional disambiguator */
	dd_rv0_ambiguator(dd);

	return dd_rv0_path(dd);
}

static int dd_rv0_lifetime(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'L');
	return dd_rv0_base62_num(dd, NULL);
}

static int dd_rv0_const(struct demangle_data *dd)
{
	int n;
	char c;
	char *p;
	bool print_type = (!dd->type || dd->type_info) && !dd->ignore_disc;
	bool old_ignore_disc = dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	c = dd_curr(dd);

	/* placeholder */
	if (c == 'p') {
		if (print_type)
			dd_append(dd, "_");

		dd->pos++;
		return 0;
	}

	/* backref */
	if (c == 'B')
		return dd_rv0_backref(dd);

	/* ignore type info of const data */
	dd->ignore_disc = true;
	if (dd_rv0_type(dd) < 0)
		return -1;
	dd->ignore_disc = old_ignore_disc;

	/* const-data */
	if (dd_curr(dd) == 'n')
		dd->pos++;

	n = strtol(&dd->old[dd->pos], &p, 16);
	if (print_type) {
		char buf[16];

		snprintf(buf, sizeof(buf), "%d", n);
		dd_append(dd, buf);
	}

	/* update position after the const-data */
	dd->pos = p - dd->old;

	DD_DEBUG_CONSUME(dd, '_');
	return 0;
}

static int dd_rv0_generic_arg(struct demangle_data *dd)
{
	char c;

	if (dd_eof(dd))
		return -1;

	dd_add_debug(dd);

	c = dd_curr(dd);

	if (c == 'L')
		return dd_rv0_lifetime(dd);
	if (c == 'K') {
		dd->pos++;
		return dd_rv0_const(dd);
	}

	return dd_rv0_type(dd);
}

static int dd_rv0_crate(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'C');
	dd->level++;

	if (dd_rv0_ident(dd) < 0)
		return -1;

	dd->level--;
	return 0;
}

static int dd_rv0_nested_path(struct demangle_data *dd)
{
	bool closure;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'N');
	dd->level++;

	closure = (dd_curr(dd) == 'C');
	dd->pos++;

	if (dd_rv0_path(dd) < 0)
		return -1;

	if (dd_rv0_ident(dd) < 0)
		return -1;

	if (closure && (!dd->type || dd->type_info) && !dd->ignore_disc) {
		dd_append_separator(dd, "::");
		dd_append(dd, "{closure}");
	}
	dd->level--;
	return 0;
}

static int dd_rv0_method_impl(struct demangle_data *dd)
{
	bool old_type_info = dd->type_info;
	bool old_ignore_disc = dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'M');
	dd->level++;

	dd_append_separator(dd, "::");

	/* ignore the impl path */
	dd->ignore_disc = true;
	if (dd_rv0_impl_path(dd) < 0)
		return -1;
	dd->ignore_disc = old_ignore_disc;

	/* want to print type name */
	if (!dd->ignore_disc)
		dd_append(dd, "<");

	/* prevent "::" at the start in the impl part */
	dd->first_name = true;

	dd->type_info = true;
	if (dd_rv0_type(dd) < 0)
		return -1;
	dd->type_info = old_type_info;

	if (!dd->ignore_disc)
		dd_append(dd, ">");

	dd->level--;
	return 0;
}

static int dd_rv0_trait_impl(struct demangle_data *dd)
{
	bool old_type_info = dd->type_info;
	bool old_ignore_disc = dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'X');
	dd->level++;

	/* ignore the impl path */
	dd->ignore_disc = true;
	if (dd_rv0_impl_path(dd) < 0)
		return -1;
	dd->ignore_disc = old_ignore_disc;

	if (!dd->ignore_disc)
		dd_append(dd, "<");

	/* prevent "::" at the start in the impl part */
	dd->first_name = true;

	/* want to print type name */
	dd->type_info = true;
	if (dd_rv0_type(dd) < 0)
		return -1;
	dd->type_info = old_type_info;

	/* ignore the target path */
	dd->ignore_disc = true;
	if (dd_rv0_path(dd) < 0)
		return -1;

	dd->ignore_disc = old_ignore_disc;
	if (!dd->ignore_disc)
		dd_append(dd, ">");

	dd->level--;
	return 0;
}

static int dd_rv0_trait_def(struct demangle_data *dd)
{
	bool old_type_info = dd->type_info;
	bool old_ignore_disc = dd->ignore_disc;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'Y');
	dd->level++;

	dd_append(dd, "<");
	/* prevent "::" at the start in the impl part */
	dd->first_name = true;

	/* want to print type name */
	dd->type_info = true;
	if (dd_rv0_type(dd) < 0)
		return -1;
	dd->type_info = old_type_info;

	/* ignore the target path */
	dd->ignore_disc = true;
	if (dd_rv0_path(dd) < 0)
		return -1;
	dd->ignore_disc = old_ignore_disc;

	dd_append(dd, ">");
	dd->level--;
	return 0;
}

static int dd_rv0_generic_args(struct demangle_data *dd)
{
	bool old_type_info = dd->type_info;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'I');
	dd->level++;

	/* want to print type name */
	dd->type_info = true;
	if (dd_rv0_type(dd) < 0)
		return -1;

	if (!dd->ignore_disc)
		dd_append(dd, "<");

	while (!dd_eof(dd) && dd_curr(dd) != 'E') {
		/* prevent "::" at the start in the args part */
		dd->first_name = true;

		if (dd_rv0_generic_arg(dd) < 0)
			return -1;
		dd_append(dd, ",");
	}
	/* remove the last comma */
	dd->newpos--;

	if (!dd->ignore_disc)
		dd_append(dd, ">");
	dd->type_info = old_type_info;

	dd->first_name = false;

	dd->level--;
	__DD_DEBUG_CONSUME(dd, 'E');
	return 0;
}

static int dd_rv0_backref(struct demangle_data *dd)
{
	int num;
	int old_pos;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'B');
	if (dd_rv0_base62_num(dd, &num) < 0)
		return -1;

	old_pos = dd->pos;
	dd->pos = num + 2; /* skip "_R" */

	if (dd_rv0_path(dd) < 0) {
		dd->pos = old_pos;
		return -1;
	}

	dd->pos = old_pos;
	return 0;
}

static int dd_rv0_path(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	switch (c) {
	case 'C': /* crate-root */
		return dd_rv0_crate(dd);
	case 'N': /* nested-path */
		return dd_rv0_nested_path(dd);
	case 'M': /* (method) inherent implementation */
		return dd_rv0_method_impl(dd);
	case 'X': /* trait implementation */
		return dd_rv0_trait_impl(dd);
	case 'Y': /* trait definition */
		return dd_rv0_trait_def(dd);
	case 'I': /* generic arguments */
		return dd_rv0_generic_args(dd);
	case 'B': /* back reference (compression) */
		return dd_rv0_backref(dd);
	default:
		break;
	}
	return -1;
}

char *demangle_rust_v0(char *str)
{
	struct demangle_data dd = {
		.old = str,
		.len = strlen(str),
		.first_name = true,
	};
	char c;

	/* "_R" prefix */
	dd_consume_n(&dd, 2);

	c = dd_curr(&dd);

	/* optional version number */
	if (isdigit(c))
		dd.pos++;

	if (dd_rv0_path(&dd) < 0) {
		dd_debug_print(&dd);
		return xstrdup(str);
	}

	/* ignore 'instantiating-crate' part */
	if (!dd_eof(&dd) && dd_curr(&dd) == 'C') {
		dd.ignore_disc = true;
		dd_rv0_path(&dd);
	}

	/* the 'instanciating-crate' can be a backref */
	if (!dd_eof(&dd) && dd_curr(&dd) == 'B') {
		dd.ignore_disc = true;
		dd_rv0_backref(&dd);
	}

	/* ignore 'vendor-specific' suffix (for compilers) */
	if (!dd_eof(&dd) && (dd_curr(&dd) != '.' && dd_curr(&dd) != '$')) {
		dd_debug_print(&dd);
		return xstrdup(str);
	}

	/* caller should free it */
	return dd.new;
}

#ifdef UNIT_TEST

#define DEMANGLE_TEST(m, d)                                                                        \
	do {                                                                                       \
		char *name = demangle(m);                                                          \
		pr_dbg("%.64s should be converted to %s\n", m, d);                                 \
		TEST_STREQ(d, name);                                                               \
		free(name);                                                                        \
	} while (0)

TEST_CASE(demangle_rust0)
{
	DEMANGLE_TEST("_RNvCs15kBYyAo9fc_7mycrate7example", "mycrate::example");
	DEMANGLE_TEST("_RNvMsr_NtCs3ssYzQotkvD_3std4pathNtB5_7PathBuf3newCs15kBYyAo9fc_7mycrate",
		      "<std::path::PathBuf>::new");
	DEMANGLE_TEST(
		"_RNvXCs15kBYyAo9fc_7mycrateNtB2_7ExampleNtB2_5Trait3foo",
		"<mycrate::Example>::foo"); /* instead of "<mycrate::Example as mycrate::Trait>::foo" */
	DEMANGLE_TEST("_RNvYNtCs15kBYyAo9fc_7mycrate7ExampleNtB4_5Trait7exampleB4_",
		      "<mycrate::Example>::example");
	DEMANGLE_TEST("_RNCNvCsgStHSCytQ6I_7mycrate4mains_0B3_", "mycrate::main::{closure}");
	DEMANGLE_TEST("_RNvNvMCsd9PVOYlP1UU_7mycrateINtB4_7ExamplepKpE3foo14EXAMPLE_STATIC",
		      "<mycrate::Example<_,_>>::foo::EXAMPLE_STATIC");
	DEMANGLE_TEST("_RINvCs7qp2U7fqm6G_7mycrate7exampleAtj8_EB2_", "mycrate::example<[u16;8]>");
	DEMANGLE_TEST("_RINvCs7qp2U7fqm6G_7mycrate7exampleNtB2_7ExampleBw_EB2_",
		      "mycrate::example<mycrate::Example,mycrate::Example>");
	DEMANGLE_TEST("_RINvMsY_NtCseXNvpPnDBDp_3std4pathNtB6_4Path3neweECs7qp2U7fqm6G_7mycrate",
		      "<std::path::Path>::new<str>");
	DEMANGLE_TEST("_RNvNvNvCs7qp2U7fqm6G_7mycrate7EXAMPLE7___getit5___KEY$tlv$init",
		      "mycrate::EXAMPLE::__getit::__KEY");
	DEMANGLE_TEST("_RNvCs466Js1JEauR_7___rustc11___rdl_alloc", "__rustc::__rdl_alloc");

	return TEST_OK;
}

#endif /* UNIT_TEST */
