/*
 * Very simple (and incomplete by design) C++ name demangler.
 *
 * Copyright (C) 2015-2019, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2 license (the C++ part).
 *
 * See https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling
 *
 * Rust demangler referred to https://github.com/alexcrichton/rustc-demangle
 * which was released by MIT (or Apache) license.
 *
 * Copyright (c) 2014 Alex Crichton
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without
 * limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
 * ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdlib.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "demangle"
#define PR_DOMAIN DBG_DEMANGLE

#include "utils/symbol.h"
#include "utils/utils.h"

#define MAX_DEBUG_DEPTH 128

enum symbol_demangler demangler = DEMANGLE_SIMPLE;

struct demangle_debug {
	const char *func;
	int level;
	int pos;
};

struct demangle_data {
	char *old;
	char *new;
	const char *func;
	char *expected;
	int line;
	int pos;
	int len;
	int newpos;
	int alloc;
	int level;
	int type;
	int nr_dbg;
	int templates;
	bool type_info;
	bool first_name;
	bool ignore_disc;
	struct demangle_debug debug[MAX_DEBUG_DEPTH];
};

static char dd_expbuf[2];

static int dd_eof(struct demangle_data *dd)
{
	return dd->pos >= dd->len;
}

static char dd_peek(struct demangle_data *dd, int lookahead)
{
	if (dd->pos + lookahead > dd->len)
		return 0;
	return dd->old[dd->pos + lookahead];
}

static char dd_curr(struct demangle_data *dd)
{
	return dd_peek(dd, 0);
}

static void __dd_add_debug(struct demangle_data *dd, const char *func)
{
	if (dd->nr_dbg < MAX_DEBUG_DEPTH && func) {
		struct demangle_debug *dbg = &dd->debug[dd->nr_dbg++];

		dbg->func = func;
		dbg->level = dd->level;
		dbg->pos = dd->pos;
	}
}

static char __dd_consume_n(struct demangle_data *dd, int n, const char *dbg)
{
	char c = dd_curr(dd);

	if (dbg)
		__dd_add_debug(dd, dbg);

	if (dd->pos + n > dd->len)
		return 0;

	dd->pos += n;
	return c;
}

static char __dd_consume(struct demangle_data *dd, const char *dbg)
{
	return __dd_consume_n(dd, 1, dbg);
}

#define dd_consume(dd) __dd_consume(dd, __func__)
#define dd_consume_n(dd, n) __dd_consume_n(dd, n, __func__)
#define dd_add_debug(dd) __dd_add_debug(dd, __func__)

#define DD_DEBUG(dd, exp, inc)                                                                     \
	({                                                                                         \
		dd->func = __func__;                                                               \
		dd->line = __LINE__ - 1;                                                           \
		dd->pos += inc;                                                                    \
		dd->expected = exp;                                                                \
		return -1;                                                                         \
	})

#define DD_DEBUG_CONSUME(dd, exp_c)                                                                \
	({                                                                                         \
		if (dd_consume(dd) != exp_c) {                                                     \
			if (!dd->expected) {                                                       \
				dd->func = __func__;                                               \
				dd->line = __LINE__;                                               \
				dd->pos--;                                                         \
				dd->expected = dd_expbuf;                                          \
				dd_expbuf[0] = exp_c;                                              \
			}                                                                          \
			return -1;                                                                 \
		}                                                                                  \
	})

#define __DD_DEBUG_CONSUME(dd, exp_c)                                                              \
	({                                                                                         \
		if (__dd_consume(dd, NULL) != exp_c) {                                             \
			if (!dd->expected) {                                                       \
				dd->func = __func__;                                               \
				dd->line = __LINE__;                                               \
				dd->pos--;                                                         \
				dd->expected = dd_expbuf;                                          \
				dd_expbuf[0] = exp_c;                                              \
			}                                                                          \
			return -1;                                                                 \
		}                                                                                  \
	})

static void dd_debug_print(struct demangle_data *dd)
{
	int i;
	const char *expected = dd->expected;

	if (expected == NULL) {
		if (dd_eof(dd))
			expected = "more input";
		else
			expected = "unknown input";
	}

	if (dd->func == NULL)
		dd->func = "demangle";

	if (dbg_domain[DBG_DEMANGLE] <= 3) {
		pr_dbg3("demangle failed: %s\n", dd->old);
		return;
	}

	pr_dbg4("simple demangle failed:%s%s\n%s\n%*c\n%s:%d: \"%s\" expected\n",
		dd_eof(dd) ? " (EOF)" : "", dd->level ? " (not finished)" : "", dd->old,
		dd->pos + 1, '^', dd->func, dd->line, expected);

	pr_dbg4("current: %s (pos: %d/%d)\n", dd->new, dd->pos, dd->len);
	for (i = 0; i < dd->nr_dbg; i++) {
		struct demangle_debug *dbg = &dd->debug[i];

		pr_dbg4("  [%02d] (%03d/%c%c) %*s%s\n", i, dbg->pos,
			dbg->pos < dd->len ? dd->old[dbg->pos] : ' ',
			dbg->pos + 1 < dd->len ? dd->old[dbg->pos + 1] : ' ', dbg->level * 2, "",
			dbg->func);
	}
}

static const struct {
	char op[2];
	char *name;
} ops[] = {
	{ { 'n', 'w' }, " new" },      { { 'n', 'a' }, " new[]" }, { { 'd', 'l' }, " delete" },
	{ { 'd', 'a' }, " delete[]" }, { { 'p', 's' }, "+" }, /* unary */
	{ { 'n', 'g' }, "-" }, /* unary */
	{ { 'a', 'd' }, "&" }, /* unary */
	{ { 'd', 'e' }, "*" }, /* unary */
	{ { 'c', 'o' }, "~" },	       { { 'p', 'l' }, "+" },	   { { 'm', 'i' }, "-" },
	{ { 'm', 'l' }, "*" },	       { { 'd', 'v' }, "/" },	   { { 'r', 'm' }, "%" },
	{ { 'a', 'n' }, "&" },	       { { 'o', 'r' }, "|" },	   { { 'e', 'o' }, "^" },
	{ { 'a', 'S' }, "=" },	       { { 'p', 'L' }, "+=" },	   { { 'm', 'I' }, "-=" },
	{ { 'm', 'L' }, "*=" },	       { { 'd', 'V' }, "/=" },	   { { 'r', 'M' }, "%=" },
	{ { 'a', 'N' }, "&=" },	       { { 'o', 'R' }, "|=" },	   { { 'e', 'O' }, "^=" },
	{ { 'l', 's' }, "<<" },	       { { 'r', 's' }, ">>" },	   { { 'l', 'S' }, "<<=" },
	{ { 'r', 'S' }, ">>=" },       { { 'e', 'q' }, "==" },	   { { 'n', 'e' }, "!=" },
	{ { 'l', 't' }, "<" },	       { { 'g', 't' }, ">" },	   { { 'l', 'e' }, "<=" },
	{ { 'g', 'e' }, ">=" },	       { { 'n', 't' }, "!" },	   { { 'a', 'a' }, "&&" },
	{ { 'o', 'o' }, "||" },	       { { 'p', 'p' }, "++" },	   { { 'm', 'm' }, "--" },
	{ { 'c', 'm' }, "," },	       { { 'p', 'm' }, "->*" },	   { { 'p', 't' }, "->" },
	{ { 'c', 'l' }, "()" },	       { { 'i', 'x' }, "[]" },	   { { 'q', 'u' }, "?" },
	{ { 'c', 'v' }, "(cast)" },    { { 'l', 'i' }, "\"\"" },
};

static const struct {
	char code;
	char *name;
} types[] = {
	{ 'v', "void" },	{ 'w', "wchar_t" },
	{ 'b', "bool" },	{ 'c', "char" },
	{ 'a', "signed char" }, { 'h', "unsigned char" },
	{ 's', "short" },	{ 't', "unsigned short" },
	{ 'i', "int" },		{ 'j', "unsigned int" },
	{ 'l', "long" },	{ 'm', "unsigned long" },
	{ 'x', "long long" },	{ 'y', "unsigned long long" },
	{ 'n', "__int128" },	{ 'o', "unsigned __int128" },
	{ 'f', "float" },	{ 'd', "double" },
	{ 'e', "long double" }, { 'g', "__float128" },
	{ 'z', "..." },
};

static const struct {
	char code;
	char *name;
} std_abbrevs[] = {
	{ 't', "std" },
	{ 'a', "std::allocator" },
	{ 'b', "std::basic_string" },
	{ 's', "std::basic_string<>" },
	{ 'i', "std::basic_istream" },
	{ 'o', "std::basic_ostream" },
	{ 'd', "std::basic_iostream" },
};

static const struct {
	char *code; /* surrounded by $..$ */
	char *punc;
} rust_mappings[] = {
	{ "SP", "@" },
	{ "BP", "*" },
	{ "RF", "&" },
	{ "LT", "<" },
	{ "GT", ">" },
	{ "LP", "(" },
	{ "RP", ")" },
	{ "C", "," },
	/* some selected unicode characters */
	{ "u20", " " },
	{ "u22", "\"" },
	{ "u27", "'" },
	{ "u2b", "+" },
	{ "u3b", ";" },
	{ "u3d", "=" },
	{ "u5b", "[" },
	{ "u5d", "]" },
	{ "u7b", "{" },
	{ "u7d", "}" },
	{ "u7e", "~" },
};

static int dd_encoding(struct demangle_data *dd);
static int dd_name(struct demangle_data *dd);
static int dd_local_name(struct demangle_data *dd);
static int dd_source_name(struct demangle_data *dd);
static int dd_operator_name(struct demangle_data *dd);
static int dd_nested_name(struct demangle_data *dd);
static int dd_unqualified_name(struct demangle_data *dd);
static int dd_type(struct demangle_data *dd);
static int dd_decltype(struct demangle_data *dd);
static int dd_expression(struct demangle_data *dd);
static int dd_expr_primary(struct demangle_data *dd);

static int dd_append_len(struct demangle_data *dd, char *str, int size)
{
	if (dd->newpos + size >= dd->alloc) {
		dd->alloc = ALIGN(dd->newpos + size + 1, 16);
		dd->new = xrealloc(dd->new, dd->alloc);
	}

	/* copy including the last NUL byte (but usually not) */
	strncpy(&dd->new[dd->newpos], str, size + 1);
	dd->newpos += size;
	dd->new[dd->newpos] = '\0';

	return 0;
}

static int dd_append(struct demangle_data *dd, char *str)
{
	return dd_append_len(dd, str, strlen(str));
}

static int dd_append_separator(struct demangle_data *dd, char *str)
{
	if (!dd->first_name)
		dd_append(dd, str);

	dd->first_name = false;
	return 0;
}

static int dd_number(struct demangle_data *dd)
{
	char *str = &dd->old[dd->pos];
	char *end;
	int num;

	if (dd_eof(dd))
		return -1;

	if (*str == 'n') {
		/* negative number */
		str++;
		dd->pos++;
	}

	if (!isdigit(*str))
		DD_DEBUG(dd, "digit", 0);

	num = strtoul(str, &end, 0);
	dd->pos += end - str;

	return num;
}

static int dd_seq_id(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	/* just skip for now */
	while (isdigit(c) || isupper(c)) {
		dd_add_debug(dd);
		c = dd->old[++dd->pos];
	}
	return 0;
}

static int dd_call_offset(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	if (c == 'h') {
		dd_consume(dd);
		if (dd_number(dd) < 0)
			return -1;
		__DD_DEBUG_CONSUME(dd, '_');
		return 0;
	}
	if (c == 'v') {
		dd_consume(dd);
		if (dd_number(dd) < 0)
			return -1;
		__DD_DEBUG_CONSUME(dd, '_');
		if (dd_number(dd) < 0)
			return -1;
		__DD_DEBUG_CONSUME(dd, '_');
		return 0;
	}
	return -1;
}

static int dd_qualifier(struct demangle_data *dd)
{
	char c = dd_curr(dd);
	char qual[] = "rVKRO";

	if (dd_eof(dd))
		return -1;

	/* qualifiers are optional and we ignore them */
	if (strchr(qual, c))
		dd_consume(dd);

	return 0;
}

static int dd_initializer(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = __dd_consume(dd, NULL);

	if (dd_eof(dd))
		return -1;

	if (c0 != 'p' || c1 != 'i')
		DD_DEBUG(dd, "pi", -2);

	dd->level++;
	while (dd_curr(dd) != 'E') {
		if (dd_expression(dd) < 0)
			return -1;
	}
	__DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
	return 0;
}

static int dd_abi_tag(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'B');

	if (dd_source_name(dd) < 0)
		return -1;

	return 0;
}

static int dd_substitution(struct demangle_data *dd)
{
	char c;
	unsigned i;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'S');

	c = dd_curr(dd);
	for (i = 0; i < ARRAY_SIZE(std_abbrevs); i++) {
		if (c == std_abbrevs[i].code) {
			__dd_consume(dd, NULL);
			if (dd->type == 0 || dd->type_info) {
				dd_append_separator(dd, "::");
				dd_append(dd, std_abbrevs[i].name);
			}

			if (dd_curr(dd) == 'B')
				dd_abi_tag(dd);
			return 0;
		}
	}

	dd_seq_id(dd);
	__DD_DEBUG_CONSUME(dd, '_');
	return 0;
}

static int dd_function_param(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = __dd_consume(dd, NULL);

	if (dd_eof(dd))
		return -1;

	if (c0 != 'f' || (c1 != 'p' && c1 != 'L'))
		DD_DEBUG(dd, "fp or fL", -2);

	if (isdigit(dd_curr(dd))) {
		dd_number(dd);

		if (c1 == 'L')
			__DD_DEBUG_CONSUME(dd, 'p');
	}

	dd_qualifier(dd);

	if (isdigit(dd_curr(dd)))
		dd_number(dd);
	__DD_DEBUG_CONSUME(dd, '_');
	return 0;
}

static int dd_template_param(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'T');

	dd_number(dd);

	__DD_DEBUG_CONSUME(dd, '_');
	return 0;
}

static int dd_template_arg(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	if (c == 'X') {
		dd_consume(dd);

		dd->level++;
		dd_expression(dd);
		__DD_DEBUG_CONSUME(dd, 'E');
		dd->level--;
	}
	else if (c == 'L') {
		if (dd_expr_primary(dd) < 0)
			return -1;
	}
	else if (c == 'J') {
		dd_consume(dd);

		dd->level++;
		while (dd_curr(dd) != 'E') {
			if (dd_template_arg(dd) < 0)
				return -1;
		}
		__DD_DEBUG_CONSUME(dd, 'E');
		dd->level--;
	}
	else {
		if (dd_type(dd) < 0)
			return -1;
	}
	return 0;
}

static int dd_template_args(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'I');

	dd->templates++;
	dd->level++;

	while (dd_curr(dd) != 'E') {
		if (dd_template_arg(dd) < 0)
			return -1;
	}
	__DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
	dd->templates--;
	return 0;
}

static int dd_simple_id(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	if (!isdigit(dd_curr(dd)))
		DD_DEBUG(dd, "digit", -1);

	if (dd_source_name(dd) < 0)
		return -1;

	if (dd_curr(dd) == 'I')
		return dd_template_args(dd);

	return 0;
}

static int dd_unresolved_type(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	if (c == 'T')
		return dd_template_param(dd);
	if (c == 'D')
		return dd_decltype(dd);
	if (c == 'S') {
		if (dd_substitution(dd) < 0)
			return -1;
		if (dd_curr(dd) == 'I')
			return dd_template_args(dd);
		if (isdigit(dd_curr(dd)))
			return dd_unqualified_name(dd);
		return 0;
	}
	return -1;
}

static int dd_destructor_name(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	if (isdigit(c))
		return dd_source_name(dd);
	return dd_unresolved_type(dd);
}

static int dd_base_unresolved_name(struct demangle_data *dd)
{
	char c0 = dd_curr(dd);
	char c1 = dd_peek(dd, 1);

	if (dd_eof(dd))
		return -1;

	if (c0 == 'o' && c1 == 'n') {
		dd_consume_n(dd, 2);
		if (dd_operator_name(dd) < 0)
			return -1;
		if (dd_curr(dd) == 'I')
			return dd_template_args(dd);
		return 0;
	}
	if (c0 == 'd' && c1 == 'n') {
		dd_consume_n(dd, 2);
		return dd_destructor_name(dd);
	}
	return dd_simple_id(dd);
}

static int dd_unresolved_name(struct demangle_data *dd)
{
	char c0 = dd_curr(dd);
	char c1 = dd_peek(dd, 1);

	if (dd_eof(dd))
		return -1;

	if (c0 == 'g' && c1 == 's') {
		__dd_consume_n(dd, 2, NULL);
		c0 = dd_curr(dd);
		c1 = dd_peek(dd, 1);
	}

	if (c0 == 's' && c1 == 'r') {
		dd_consume_n(dd, 2);

		c0 = dd_curr(dd);
		if (c0 == 'T' || c0 == 'D' || c0 == 'S') {
			if (dd_type(dd) < 0)
				return -1;

			if (dd_base_unresolved_name(dd) < 0)
				return -1;

			if (dd_curr(dd) == 'I')
				dd_template_args(dd);

			return 0;
		}

		if (c0 == 'N') {
			__dd_consume(dd, NULL);
			if (dd_type(dd) < 0)
				return -1;
		}

		c0 = dd_curr(dd);
		while (c0 != 'E') {
			if (dd_simple_id(dd) < 0)
				return 0;
			c0 = dd_curr(dd);
		}

		if (c0 != 'E')
			pr_dbg("no E\n");

		__DD_DEBUG_CONSUME(dd, 'E');
	}

	return dd_base_unresolved_name(dd);
}

static int dd_expr_primary(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'L');

	dd->type++;
	dd->level++;

	if (dd_curr(dd) == '_' && dd_peek(dd, 1) == 'Z') {
		__dd_consume_n(dd, 2, NULL);

		if (dd_encoding(dd) < 0)
			return -1;
		__DD_DEBUG_CONSUME(dd, 'E');

		dd->level--;
		dd->type--;

		return 0;
	}

	dd_type(dd);
	dd_number(dd);
	if (dd_curr(dd) == '_') {
		__dd_consume(dd, NULL);
		dd_number(dd);
	}

	__DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
	dd->type--;
	return 0;
}

static int dd_expr_list(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	dd->level++;
	while (c != 'E' && c != '_') {
		if (dd_expression(dd) < 0)
			return -1;
		c = dd_curr(dd);
	}
	__dd_consume_n(dd, 1, NULL);
	dd->level--;
	return 0;
}

static int dd_expression(struct demangle_data *dd)
{
	unsigned i;
	char c0 = dd_peek(dd, 0);
	char c1 = dd_peek(dd, 1);
	char *exp = &dd->old[dd->pos];
	char *unary_ops[] = {
		"ps", "ng", "ad", "de", "pp_", "mm_", "pp", "mm", "dl",
		"da", "te", "sz", "az", "nx",  "sp",  "tw", "nt",
	};

	if (dd_eof(dd))
		return -1;

	dd_add_debug(dd);

	if (c0 == 'g' && c1 == 's') {
		__dd_consume_n(dd, 2, NULL);
		c0 = dd_curr(dd);
		c1 = dd_peek(dd, 1);
	}

	if (c0 == 'L')
		return dd_expr_primary(dd);

	for (i = 0; i < ARRAY_SIZE(unary_ops); i++) {
		/* unary operator */
		if (strncmp(unary_ops[i], exp, strlen(unary_ops[i])))
			continue;
		dd_consume_n(dd, strlen(unary_ops[i]));
		return dd_expression(dd);
	}
	if (c0 == 'q' && c1 == 'u') {
		/* ternary operator */
		dd_consume_n(dd, 2);
		if (dd_expression(dd) < 0)
			return -1;
		if (dd_expression(dd) < 0)
			return -1;
		return dd_expression(dd);
	}
	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		/* binary operator */
		if (c0 != ops[i].op[0] || c1 != ops[i].op[1])
			continue;
		if (c0 == 'c' || c1 == 'v')
			continue;
		dd_consume_n(dd, 2);
		if (dd_expression(dd) < 0)
			return -1;
		return dd_expression(dd);
	}
	if (c0 == 'c' && c1 == 'l') {
		dd_consume_n(dd, 2);
		return dd_expr_list(dd);
	}
	if (c0 == 'c' && c1 == 'v') {
		dd_consume_n(dd, 2);
		if (dd_type(dd) < 0)
			return -1;
		if (dd_curr(dd) == '_') {
			dd_consume(dd);
			return dd_expr_list(dd);
		}
		return dd_expression(dd);
	}
	if (c0 == 't' && c1 == 'l') {
		dd_consume_n(dd, 2);
		if (dd_type(dd) < 0)
			return -1;
		return dd_expr_list(dd);
	}
	if (c0 == 'i' && c1 == 'l') {
		dd_consume_n(dd, 2);
		return dd_expr_list(dd);
	}
	if (c0 == 'n' && (c1 == 'w' || c1 == 'a')) {
		if (dd_expr_list(dd) < 0)
			return -1;
		if (dd_type(dd) < 0)
			return -1;
		if (dd_curr(dd) == 'E') {
			dd_consume(dd);
			return 0;
		}
		return dd_initializer(dd);
	}
	if (strchr("dscr", c0) && c1 == 'c') {
		dd_consume_n(dd, 2);
		if (dd_type(dd) < 0)
			return -1;
		return dd_expression(dd);
	}
	if ((c0 == 't' && c1 == 'i') || ((c0 == 's' || c0 == 'a') && c1 == 't')) {
		dd_consume_n(dd, 2);
		return dd_type(dd);
	}
	if (c0 == 'T' && (c1 == '_' || isdigit(c1))) {
		return dd_template_param(dd);
	}
	if (c0 == 'f' && (c1 == 'p' || c1 == 'L')) {
		return dd_function_param(dd);
	}
	if ((c0 == 'd' || c0 == 'p') && c1 == 't') {
		dd_consume_n(dd, 2);
		if (dd_expression(dd) < 0)
			return -1;
		return dd_unresolved_name(dd);
	}
	if (c0 == 'd' && c1 == 's') {
		dd_consume_n(dd, 2);
		if (dd_expression(dd) < 0)
			return -1;
		return dd_expression(dd);
	}
	if (c0 == 's' && c1 == 'Z') {
		dd_consume_n(dd, 2);
		c0 = dd_curr(dd);
		if (c0 == 'T')
			return dd_template_param(dd);
		if (c0 == 'f')
			return dd_function_param(dd);
		return -1;
	}
	if (c0 == 's' && c1 == 'P') {
		dd_consume_n(dd, 2);

		dd->level++;
		while (dd_curr(dd) != 'E') {
			if (dd_template_arg(dd) < 0)
				return -1;
		}
		__DD_DEBUG_CONSUME(dd, 'E');
		dd->level--;
		return 0;
	}
	if (c0 == 't' && c1 == 'r') {
		dd_consume_n(dd, 2);
		return 0;
	}

	return dd_unresolved_name(dd);
}

static int dd_function_type(struct demangle_data *dd)
{
	char c;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'F');

	c = dd_curr(dd);
	if (c == 'Y')
		__dd_consume(dd, NULL);

	dd->type++;
	dd->level++;

	c = dd_curr(dd);
	while (c != 'E') {
		int old_pos = dd->pos;

		if (dd_type(dd) < 0) {
			dd->pos = old_pos;
			break;
		}

		c = dd_curr(dd);
	}

	if (c == 'R' || c == 'O')
		dd_qualifier(dd);

	__DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
	dd->type--;
	return 0;
}

static int dd_array_type(struct demangle_data *dd)
{
	char c;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'A');

	c = dd_curr(dd);
	if (isdigit(c))
		dd_number(dd);
	else if (c != '_')
		dd_expression(dd); /* optional */

	__DD_DEBUG_CONSUME(dd, '_');

	return dd_type(dd);
}

static int dd_ptr_to_member_type(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'M');

	if (dd_type(dd) < 0) /* class */
		return -1;
	return dd_type(dd); /* member */
}

static int dd_decltype(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = __dd_consume(dd, NULL);

	if (dd_eof(dd))
		return -1;

	if (c0 != 'D' || (c1 != 'T' && c1 != 't'))
		DD_DEBUG(dd, "DT or Dt", -2);

	dd->type++;
	dd->level++;

	dd_expression(dd);

	__DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
	dd->type--;
	return 0;
}

static int dd_vector_type(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = __dd_consume(dd, NULL);

	if (dd_eof(dd))
		return -1;

	if (c0 != 'D' || c1 != 'v')
		DD_DEBUG(dd, "Dv", -2);

	dd->type++;

	c0 = dd_curr(dd);
	if (c0 == '_') {
		__dd_consume(dd, NULL);
		dd_expression(dd);
	}
	else if (dd_number(dd) < 0)
		return -1;

	__DD_DEBUG_CONSUME(dd, '_');

	dd->type--;
	return 0;
}

static int dd_type(struct demangle_data *dd)
{
	unsigned i;
	char cv_qual[] = "rVK";
	char prefix[] = "PROCG";
	char D_types[] = "defhisacnu";
	char scue[] = "sue"; /* struct, class, union, enum */
	int done = 0;
	int ret = -1;

	if (dd_eof(dd))
		return -1;

	/* ignore type names */
	dd->type++;
	dd_add_debug(dd);
	dd->level++;

	while (!done && !dd_eof(dd)) {
		char c = dd_curr(dd);

		if (strchr(cv_qual, c)) {
			dd_qualifier(dd);
			continue;
		}
		else if (strchr(prefix, c)) {
			dd_consume(dd);
			continue;
		}
		else if (c == 'F') {
			ret = dd_function_type(dd);
			done = 1;
		}
		else if (c == 'T') {
			c = dd_peek(dd, 1);
			if (strchr(scue, c)) {
				/* struct, class, union, enum */
				dd_consume_n(dd, 2);
				ret = dd_name(dd);
			}
			else if (c == '_' || isdigit(c)) {
				ret = dd_template_param(dd);
				if (dd_curr(dd) == 'I')
					ret = dd_template_args(dd);
			}
			done = 1;
		}
		else if (c == 'A') {
			ret = dd_array_type(dd);
			done = 1;
		}
		else if (c == 'M') {
			ret = dd_ptr_to_member_type(dd);
			done = 1;
		}
		else if (c == 'D') {
			c = dd_peek(dd, 1);
			if (strchr(D_types, c)) {
				dd_consume_n(dd, 2);
				ret = 0;
			}
			else if (c == 'p') {
				/* pack expansion */
				dd_consume_n(dd, 2);
				continue;
			}
			else if (c == 'v') {
				dd_vector_type(dd);
				continue;
			}
			else if (c == 't' || c == 'T')
				ret = dd_decltype(dd);
			done = 1;
		}
		else if (c == 'S') {
			c = dd_peek(dd, 1);
			ret = dd_substitution(dd);
			if (!ret && c == 't' && isdigit(dd_curr(dd)))
				ret = dd_unqualified_name(dd);
			if (dd_curr(dd) == 'I')
				ret = dd_template_args(dd);
			done = 1;
		}
		else if (c == 'u') {
			/* vendor extended type */
			dd_consume(dd);
			ret = dd_source_name(dd);
			done = 1;
		}
		else if (c == 'U') {
			/* vendor extended type qualifier */
			dd_consume(dd);
			ret = dd_source_name(dd);
			if (ret < 0)
				done = 1;

			if (!ret && dd_curr(dd) == 'I')
				ret = dd_template_args(dd);
			if (ret < 0)
				done = 1;
		}
		else if (c == 'I') {
			/* template args?? - not specified in the spec */
			ret = dd_template_args(dd);
			done = 1;
		}
		else if (isdigit(c) || c == 'N' || c == 'Z') {
			/* class or enum name */
			ret = dd_name(dd);
			done = 1;
		}
		else {
			/* builtin types */
			for (i = 0; i < ARRAY_SIZE(types); i++) {
				if (c == types[i].code) {
					__dd_consume(dd, NULL);
					ret = 0;
					break;
				}
			}
			done = 1;
		}
	}

	dd->level--;
	dd->type--;
	return ret;
}

static int dd_discriminator(struct demangle_data *dd)
{
	char c;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, '_');

	c = dd_curr(dd);
	if (isdigit(c)) {
		return dd_number(dd) > 0 ? 0 : -1;
	}
	else if (c == '_') {
		__dd_consume(dd, NULL);
		if (dd_number(dd) < 0)
			return -1;
		__DD_DEBUG_CONSUME(dd, '_');
	}
	return 0;
}

static int dd_special_name(struct demangle_data *dd)
{
	char c0 = dd_curr(dd);
	char c1 = dd_peek(dd, 1);
	char T_type[] = "VTISFJ";
	char *T_type_name[] = { "vtable",   "VTT",	   "typeinfo_name",
				"typeinfo", "typeinfo_fn", "java_class" };

	if (dd_eof(dd))
		return -1;

	if (c0 == 'T') {
		if (strchr(T_type, c1)) {
			int idx;
			char *p;

			dd_consume_n(dd, 2);
			dd->type_info = true;

			p = strchr(T_type, c1);
			idx = p - T_type;
			/* special name prefix */
			dd_append(dd, "__");
			dd_append(dd, T_type_name[idx]);
			dd_append(dd, "__");

			return dd_type(dd);
		}
		if (c1 == 'h' || c1 == 'v') {
			dd_consume(dd);
			if (dd_call_offset(dd) < 0)
				return -1;
			return dd_encoding(dd);
		}
		if (c1 == 'c') {
			dd_consume_n(dd, 2);
			if (dd_call_offset(dd) < 0)
				return -1;
			if (dd_call_offset(dd) < 0)
				return -1;
			return dd_encoding(dd);
		}
		if (c1 == 'C') {
			dd_consume_n(dd, 2);
			dd_append(dd, "__construction_vtable__");

			/* base type */
			dd->type_info = true;
			if (dd_type(dd) < 0)
				return -1;

			if (dd_number(dd) < 0)
				return -1;
			if (dd_eof(dd))
				return 0;
			__DD_DEBUG_CONSUME(dd, '_');

			/*
			 * ideally it'd be better using this derived type
			 * for the simple name but it requires to support
			 * substitution correctly which is not done yet.
			 * So just use the base type info only.
			 */
			dd->type_info = false;
			return dd_type(dd);
		}
		if (c1 == 'H' || c1 == 'W') {
			/* TLS init and wrapper */
			dd_consume_n(dd, 2);
			dd_append_separator(dd, "::");
			dd_append(dd, "TLS_");
			dd_append(dd, c1 == 'H' ? "init" : "wrap");
			return dd_name(dd);
		}
	}
	if (c0 == 'G') {
		if (c1 == 'V') {
			/* guard */
			dd_consume_n(dd, 2);
			dd_append(dd, "__guard_variable__");
			return dd_name(dd);
		}
		if (c1 == 'R') {
			/* reftemp */
			dd_consume_n(dd, 2);
			dd_append(dd, "__ref_temp__");

			dd->ignore_disc = true;
			if (dd_name(dd) < 0)
				return -1;

			if (dd_curr(dd) != '_')
				dd_seq_id(dd);
			__DD_DEBUG_CONSUME(dd, '_');
			return 0;
		}
		if (c1 == 'A') {
			/* hidden alias */
			dd_consume_n(dd, 2);
			return dd_encoding(dd);
		}
		if (c1 == 'T') {
			dd_consume_n(dd, 2);

			c0 = dd_curr(dd);
			/* (non-)transaction clone */
			if (c0 == 't' || c0 == 'n') {
				dd_consume(dd);
				return dd_encoding(dd);
			}

			return -1;
		}
	}

	DD_DEBUG(dd, "valid special name", 0);
	return 0;
}

static int dd_ctor_dtor_name(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = __dd_consume(dd, NULL);
	char *pos;
	int len;
	int ret = 0;
	bool needs_type = false;

	if (dd_eof(dd))
		return -1;

	if ((c0 != 'C' && c0 != 'D'))
		DD_DEBUG(dd, "C[0-5] or D[0-5]", -2);

	/* inheriting constructor */
	if (c1 == 'I') {
		c1 = __dd_consume(dd, NULL);
		needs_type = true;
	}

	if (!isdigit(c1))
		DD_DEBUG(dd, "C[0-5] or D[0-5]", -2 - (needs_type ? 1 : 0));

	if (needs_type)
		ret = dd_type(dd);

	if (dd->type)
		return ret;

	/* repeat last name after '::' */
	pos = strrchr(dd->new, ':');
	if (pos == NULL)
		pos = dd->new;
	else
		pos++;

	/* pos can be invalidated after dd_apend() below, so copy it */
	pos = xstrdup(pos);
	len = strlen(pos);

	if (c0 == 'C')
		dd_append(dd, "::");
	else
		dd_append(dd, "::~");

	dd_append_len(dd, pos, len);
	free(pos);
	return ret;
}

static int dd_operator_name(struct demangle_data *dd)
{
	unsigned i;
	char c0 = dd_consume(dd);
	char c1 = __dd_consume(dd, NULL);

	if (dd_eof(dd))
		return -1;

	if (dd->type) {
		if (c0 == 'c' && c1 == 'v')
			dd_type(dd);
		if (c0 == 'l' && c1 == 'i')
			dd_source_name(dd);
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		if (c0 == ops[i].op[0] && c1 == ops[i].op[1]) {
			dd_append_separator(dd, "::");
			dd_append(dd, "operator");
			dd_append(dd, ops[i].name);

			dd->type++;
			if (c0 == 'c' && c1 == 'v')
				dd_type(dd);
			if (c0 == 'l' && c1 == 'i')
				dd_source_name(dd);
			dd->type--;

			return 0;
		}
	}
	if (c0 == 'v' && isdigit(c1)) {
		/* vender extended operator */
		dd->type++;
		dd_source_name(dd);
		dd->type--;
	}

	DD_DEBUG(dd, "valid operator name", -2);
	return 0;
}

static int dd_source_name(struct demangle_data *dd)
{
	int num = dd_number(dd);
	char *dollar;
	char *p, *end;
	unsigned i;
	bool add_name = false;

	if (num < 0)
		return -1;

	if (dd_eof(dd) || dd->pos + num > dd->len)
		DD_DEBUG(dd, "shorter name", 0);

	dd_add_debug(dd);

	if (dd->type && !dd->type_info)
		goto out;

	if (dd->templates)
		goto out;

	/* ignore hash code in a Rust symbol */
	if (num == 17 && dd->old[dd->pos] == 'h') {
		for (i = 1; i < 17; i++) {
			if (!isxdigit(dd->old[dd->pos + i]))
				break;
		}

		if (i == 17)
			goto out;
	}

	add_name = true;
	dd_append_separator(dd, "::");

	p = dd->old + dd->pos;
	dollar = strchr(p, '$');
	if (dollar == NULL)
		goto out;

	end = p + num;
	if (dollar > end)
		goto out;

	/* check special symbol mappings (e.g. '$LT$') for Rust */
	while (dollar != NULL && dollar < end) {
		bool found = false;

		num = dollar - p;
		dd_append_len(dd, p, num);

		for (i = 0; i < ARRAY_SIZE(rust_mappings); i++) {
			if (strncmp(rust_mappings[i].code, dollar + 1,
				    strlen(rust_mappings[i].code)))
				continue;

			dd_add_debug(dd);
			dd_append(dd, rust_mappings[i].punc);
			num += strlen(rust_mappings[i].code) + 2;
			__dd_consume_n(dd, num, NULL);

			p += num;
			found = true;
			break;
		}

		/* treat '$' as a normal symbol */
		if (!found)
			break;

		dollar = strchr(p, '$');
	}
	num = end - p;

out:
	if (add_name)
		dd_append_len(dd, p, num);
	__dd_consume_n(dd, num, NULL);
	return 0;
}

static int dd_unqualified_name(struct demangle_data *dd)
{
	char c0 = dd_curr(dd);
	char c1 = dd_peek(dd, 1);
	int ret = 0;

	if (dd_eof(dd))
		return -1;

	if (c0 == 'C' || c0 == 'D')
		ret = dd_ctor_dtor_name(dd);
	else if (c0 == 'U') {
		if (c1 == 't') {
			/* unnamed type name */
			dd->type++;

			dd_consume_n(dd, 2);
			dd_number(dd);
			DD_DEBUG_CONSUME(dd, '_');

			dd->type--;
		}
		else if (c1 == 'l') {
			int n = -1;
			char buf[32];

			/* closure type name (or lambda) */
			dd_consume_n(dd, 2);

			dd->level++;
			while (dd_curr(dd) != 'E') {
				if (dd_type(dd) < 0)
					break;
			}
			DD_DEBUG_CONSUME(dd, 'E');
			dd->level--;

			if (dd_curr(dd) != '_') {
				n = dd_number(dd);
				if (n < 0)
					return -1;
			}
			DD_DEBUG_CONSUME(dd, '_');

			if (dd->type)
				return 0;

			dd_append_separator(dd, "::");
			snprintf(buf, sizeof(buf), "$_%d", n + 1);
			dd_append(dd, buf);
		}
		else {
			ret = -1;
		}
	}
	else if (islower(c0))
		ret = dd_operator_name(dd);
	else {
		if (c0 == 'L')
			dd_consume(dd); /* local-source-name ? */
		ret = dd_source_name(dd);
	}

	if (dd_curr(dd) == 'B')
		ret = dd_abi_tag(dd);

	return ret;
}

static int dd_nested_name(struct demangle_data *dd)
{
	char qual[] = "rVKRO";
	int ret = 0;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'N');
	dd->level++;

	while (dd_curr(dd) != 'E' && !dd_eof(dd) && !ret) {
		char c0 = dd_curr(dd);
		char c1 = dd_peek(dd, 1);

		if (c0 == 'D' && (c1 == 'T' || c1 == 't'))
			ret = dd_decltype(dd);
		else if (c0 == 'C' || c0 == 'D')
			ret = dd_ctor_dtor_name(dd);
		else if (c0 == 'U' || islower(c0) || isdigit(c0))
			ret = dd_unqualified_name(dd);
		else if (c0 == 'T')
			ret = dd_template_param(dd);
		else if (c0 == 'I')
			ret = dd_template_args(dd);
		else if (c0 == 'S')
			ret = dd_substitution(dd);
		else if (c0 == 'M')
			dd_consume(dd); /* assumed data-member-prefix */
		else if (c0 == 'L')
			dd_consume(dd); /* local-source-name ? */
		else if (strchr(qual, c0))
			dd_qualifier(dd);
		else
			break;
	}

	__DD_DEBUG_CONSUME(dd, 'E');
	dd->level--;

	return ret;
}

static int dd_local_name(struct demangle_data *dd)
{
	char c;

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'Z');

	dd->level++;
	dd_encoding(dd);
	__DD_DEBUG_CONSUME(dd, 'E');
	dd->level--;

	c = dd_curr(dd);
	if (c == 'd') {
		__dd_consume(dd, NULL);
		if (dd_curr(dd) != '_' && dd_number(dd) < 0)
			return -1;
		__DD_DEBUG_CONSUME(dd, '_');
		if (dd_name(dd) < 0)
			return -1;
		return 0;
	}

	if (c == 's')
		__dd_consume(dd, NULL);
	else
		dd_name(dd);

	if (dd_curr(dd) == '_' && !dd->ignore_disc)
		dd_discriminator(dd);

	return 0;
}

static int dd_name(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	if (c == 'N')
		return dd_nested_name(dd);
	if (c == 'Z')
		return dd_local_name(dd);
	if (c == 'S') {
		if (dd_substitution(dd) < 0)
			return -1;

		if (dd_curr(dd) == 'I')
			return dd_template_args(dd);
	}
	if (dd_unqualified_name(dd) < 0)
		return -1;
	if (dd_curr(dd) == 'I')
		return dd_template_args(dd);
	return 0;
}

static int dd_encoding(struct demangle_data *dd)
{
	int ret;
	char c;
	char end[] = "E.@";

	if (dd_eof(dd))
		return -1;

	if (dd->pos == 0)
		dd_consume_n(dd, 2); /* skip initial "_Z" */
	else
		dd_add_debug(dd);

	dd->level++;

	c = dd_curr(dd);
	if (c == 'T' || c == 'G') {
		ret = dd_special_name(dd);
		dd->level--;
		return ret;
	}

	ret = dd_name(dd);
	if (ret < 0)
		return ret;

	while (!dd_eof(dd) && !strchr(end, dd_curr(dd))) {
		if (dd_type(dd) < 0)
			break;
	}

	/* ignore compiler generated suffix: XXX.part.0 */
	if (dd_curr(dd) == '.')
		dd->len = dd->pos;
	/* ignore version info in PLT symbols: malloc@GLIBC2.1 */
	if (dd_curr(dd) == '@')
		dd->len = dd->pos;

	dd->level--;
	return 0;
}

static char *demangle_simple(char *str)
{
	struct demangle_data dd = {
		.old = str,
		.len = strlen(str),
		.first_name = true,
	};
	bool has_prefix = false;

	if (!strncmp(str, "_GLOBAL__sub_I_", 15)) {
		has_prefix = true;
		dd.old += 15;
		dd.len -= 15;
	}

	if (dd.old[0] != '_' || dd.old[1] != 'Z')
		return xstrdup(str);

	if (dd_encoding(&dd) < 0 || dd.level != 0) {
		dd_debug_print(&dd);
		free(dd.new);
		return xstrdup(str);
	}

	if (!dd_eof(&dd)) {
		if (!dd.type_info || dd_name(&dd) < 0) {
			dd_debug_print(&dd);
			free(dd.new);
			return xstrdup(str);
		}
	}

	if (has_prefix) {
		char *p = NULL;

		xasprintf(&p, "_GLOBAL__sub_I_%s", dd.new);
		free(dd.new);
		dd.new = p;
	}

	/* caller should free it */
	return dd.new;
}

#ifdef HAVE_CXA_DEMANGLE
static char *demangle_full(char *str)
{
	char *symname;
	size_t len = 64; /* minimum length */
	int status;

	__cxa_demangle(str, NULL, &len, &status);
	if (status < 0)
		return xstrdup(str);

	symname = xmalloc(len);
	__cxa_demangle(str, symname, &len, &status);

	return symname;
}
#endif

/**
 * demangle - demangle if given @str is a mangled C++ symbol name
 * @str: symbol name
 *
 * This function returns malloc-ed string of demangled name of @str.
 * If @str is not a C++ symbol or @demangler global variable is set to
 * #DEMANGLE_NONE, the returned string is same as the input string.
 * If @demangler is #DEMANGLE_SIMPLE, it'd be demangled using our own
 * implementation.  If @demangler is #DEMANGLE_FULL, it'd be demangled
 * using libstdc++ (if available).
 */
char *demangle(char *str)
{
	if (str == NULL)
		return NULL;

	switch (demangler) {
	case DEMANGLE_SIMPLE:
		return demangle_simple(str);
	case DEMANGLE_FULL:
		return demangle_full(str);
	case DEMANGLE_NONE:
		return xstrdup(str);
	default:
		pr_dbg("demangler error\n");
		return xstrdup(str);
	}
}

#ifdef UNIT_TEST

#define DEMANGLE_TEST(m, d)                                                                        \
	do {                                                                                       \
		char *name = demangle_simple(m);                                                   \
		pr_dbg("%.64s should be converted to %s\n", m, d);                                 \
		TEST_STREQ(d, name);                                                               \
		free(name);                                                                        \
	} while (0)

TEST_CASE(demangle_simple1)
{
	DEMANGLE_TEST("normal", "normal");
	DEMANGLE_TEST("_ZN3ABC3fooEv", "ABC::foo");
	DEMANGLE_TEST("_ZN3ABCC1Ei", "ABC::ABC");
	DEMANGLE_TEST("_Znwm", "operator new");
	DEMANGLE_TEST("_ZN2ns3ns13foo4bar1Ev", "ns::ns1::foo::bar1");

	return TEST_OK;
}

TEST_CASE(demangle_simple2)
{
	DEMANGLE_TEST("_ZThn8_N13FtraceServiceD0Ev", "FtraceService::~FtraceService");
	DEMANGLE_TEST("_ZN2v88internal12ScopedVectorIcEC1Ei",
		      "v8::internal::ScopedVector::ScopedVector");
	DEMANGLE_TEST("_ZNSt16allocator_traitsISaISt13_Rb_tree_node"
		      "ISt4pairIKSsN7pbnjson7JSchemaEEEEE9construct"
		      "IS6_IS1_ISsS4_EEEEDTcl12_S_constructfp_fp0_"
		      "spcl7forwardIT0_Efp1_EEERS7_PT_DpOSB_",
		      "std::allocator_traits::construct");

	return TEST_OK;
}

TEST_CASE(demangle_simple3)
{
	DEMANGLE_TEST("_ZN4node8Watchdog7DestroyEv.part.0", "node::Watchdog::Destroy");
	DEMANGLE_TEST("_ZN2v88internal8CodeStub6GetKeyEv.constprop.17",
		      "v8::internal::CodeStub::GetKey");
	DEMANGLE_TEST("_ZSteqIPN2v88internal8compiler4NodeERKS4_PS5_E"
		      "bRKSt15_Deque_iteratorIT_T0_T1_ESE_",
		      "std::operator==");
	DEMANGLE_TEST("_ZN2v84base8internalmlIiiEENS1_14CheckedNumeric"
		      "INS1_19ArithmeticPromotionIT_T0_XqugtsrNS1_"
		      "11MaxExponentIS5_EE5valuesrNS7_IS6_EE5value"
		      "qugtsrS8_5valueL_ZNS7_IiE5valueEELNS1_"
		      "27ArithmeticPromotionCategoryE0ELSB_2E"
		      "qugtsrS9_5valueL_ZNSA_5valueEELSB_1ELSB_2EEE"
		      "4typeEEERKNS3_IS5_EES6_",
		      "v8::base::internal::operator*");
	DEMANGLE_TEST("_ZSt3powIidEN9__gnu_cxx11__promote_2IT_T0_NS0_"
		      "9__promoteIS2_XsrSt12__is_integerIS2_E7__valueEE"
		      "6__typeENS4_IS3_XsrS5_IS3_E7__valueEE6__typeEE"
		      "6__typeES2_S3_",
		      "std::pow");

	return TEST_OK;
}

TEST_CASE(demangle_simple4)
{
	DEMANGLE_TEST("_ZSt9__find_ifISt14_List_iteratorISt10shared_ptr"
		      "I16AppLaunchingItemEEZN13MemoryChecker8add_itemE"
		      "S1_I13LaunchingItemEEUlS7_E_ET_S9_S9_T0_"
		      "St18input_iterator_tag",
		      "std::__find_if");
	DEMANGLE_TEST("_ZZ19convertToWindowTypeRKSsRSsENUt_D1Ev",
		      "convertToWindowType::~convertToWindowType");
	DEMANGLE_TEST("_ZNSt3setISsSt4lessISsESaISsEE5eraseB5cxx11E"
		      "St23_Rb_tree_const_iteratorISsE",
		      "std::set::erase::cxx11");
	DEMANGLE_TEST("_ZNSt16allocator_traitsISaISsEE9_S_select"
		      "IKS0_EENSt9enable_ifIXntsrNS1_15__select_helper"
		      "IT_EE5valueES6_E4typeERS6_",
		      "std::allocator_traits::_S_select");
	DEMANGLE_TEST("_ZN6icu_5416umtx_loadAcquireERU7_Atomici", "icu_54::umtx_loadAcquire");

	return TEST_OK;
}

TEST_CASE(demangle_simple5)
{
	DEMANGLE_TEST("_ZN2v88internal13RememberedSetILNS0_"
		      "16PointerDirectionE1EE7IterateIZNS3_"
		      "18IterateWithWrapperIPFvPPNS0_10HeapObjectE"
		      "S7_EEEvPNS0_4HeapET_EUlPhE_EEvSC_SD_",
		      "v8::internal::RememberedSet::Iterate");
	DEMANGLE_TEST("_ZN2v88internal7SlotSet7Iterate"
		      "IZNS0_13RememberedSetILNS0_16PointerDirectionE"
		      "1EE18IterateWithWrapperIPFvPPNS0_10HeapObjectE"
		      "S8_EEEvPNS0_4HeapET_EUlPhE_EEiSE_",
		      "v8::internal::SlotSet::Iterate");
	DEMANGLE_TEST("_ZNSt5tupleIJPbSt14default_deleteIA_bEEEC2Ev", "std::tuple::tuple");
	DEMANGLE_TEST("_Z26storageIndexFromLayoutItemRK"
		      "N51_GLOBAL__N_kernel_qformlayout.cpp_C3DE8A26_2E30FA86"
		      "17FixedColumnMatrixIP15QFormLayoutItemLi2EEES2_",
		      "storageIndexFromLayoutItem");
	DEMANGLE_TEST("_ZGTtNSt11range_errorD1Ev", "std::range_error::~range_error");
	DEMANGLE_TEST("_ZNSi6ignoreEl@@GLIBCXX_3.4.5", "std::basic_istream::ignore");
	DEMANGLE_TEST("_ZN4llvm12function_refIFN5clang12ActionResult"
		      "IPNS1_4ExprELb1EEES4_EE11callback_fnIZNS1_4Sema"
		      "25CorrectDelayedTyposInExprES4_PNS1_7VarDeclE"
		      "S7_Ed_NUlS4_E_EEES5_lS4_",
		      "llvm::function_ref::callback_fn");

	return TEST_OK;
}

TEST_CASE(demangle_simple6)
{
	DEMANGLE_TEST("_ZN4base8internal15OptionalStorageImLb1ELb1EE"
		      "CI2NS0_19OptionalStorageBaseImLb1EEEIJRKmEEE"
		      "NS_10in_place_tEDpOT_",
		      "base::internal::OptionalStorage::OptionalStorage");
	DEMANGLE_TEST("_ZL18color_lookup_tableILi3EEv"
		      "PK28SkJumper_ColorLookupTableCtx"
		      "RDv4_fS4_S4_S3_Dv4_jS5_",
		      "color_lookup_table");
	DEMANGLE_TEST("_ZTWN6__xray19__xray_fdr_internal7RunningE",
		      "TLS_wrap::__xray::__xray_fdr_internal::Running");

	return TEST_OK;
}

TEST_CASE(demangle_simple7)
{
	DEMANGLE_TEST("_ZTSSt12system_error", "__typeinfo__std::system_error");
	DEMANGLE_TEST("_ZNSs4nposE", "std::basic_string<>::npos");
	DEMANGLE_TEST("_ZNSt14numeric_limitsIoE5radixE", "std::numeric_limits::radix");
	DEMANGLE_TEST("_ZGVNSt7__cxx117collateIcE2idE",
		      "__guard_variable__std::__cxx11::collate::id");
	DEMANGLE_TEST("_ZNSbIwSt11char_traitsIwESaIwEE4nposE", "std::basic_string::npos");

	return TEST_OK;
}

TEST_CASE(demangle_simple8)
{
	DEMANGLE_TEST("_ZTV23SkCanvasVirtualEnforcerI8SkCanvasE",
		      "__vtable__SkCanvasVirtualEnforcer");
	DEMANGLE_TEST("_ZZNK13SkImageShader14onAppendStagesE"
		      "RKN12SkShaderBase8StageRecEENK3$_0clEv",
		      "SkImageShader::onAppendStages::$_0::operator()");
	DEMANGLE_TEST("_ZTCN2v88internal12StdoutStreamE0_NS0_8OFStreamE",
		      "__construction_vtable__v8::internal::StdoutStream");
	DEMANGLE_TEST("_ZGRZNK5blink8Variable27GetPropertyNameAtomicStringEvE4name_",
		      "__ref_temp__blink::Variable::GetPropertyNameAtomicString::name");
	DEMANGLE_TEST("_ZNSt14numeric_limitsIDuE8is_exactE", "std::numeric_limits::is_exact");
	DEMANGLE_TEST("_ZTCSt10istrstream0_Si", "__construction_vtable__std::istrstream");
	DEMANGLE_TEST(
		"_ZTCNSt7__cxx1119basic_istringstreamIwSt11char_traitsIwESaIwEEE0_St13basic_istreamIwS2_E",
		"__construction_vtable__std::__cxx11::basic_istringstream::std::std::allocator");

	return TEST_OK;
}

TEST_CASE(demangle_rust1)
{
	DEMANGLE_TEST("_ZN8$BP$test3fooE", "*test::foo");
	DEMANGLE_TEST("_ZN35Bar$LT$$u5b$u32$u3b$$u20$4$u5d$$GT$E", "Bar<[u32; 4]>");
	DEMANGLE_TEST("_ZN71_$LT$Test$u20$$u2b$$u20$$u27$static"
		      "$u20$as$u20$foo..Bar$LT$Test$GT$$GT$3barE",
		      "_<Test + 'static as foo..Bar<Test>>::bar");
	DEMANGLE_TEST("_ZN3foo3bar17h05af221e174051e9E", "foo::bar");

	return TEST_OK;
}

#endif /* UNIT_TEST */
