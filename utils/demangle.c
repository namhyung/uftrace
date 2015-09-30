/*
 * Very simple (and incomplete by design) C++ name demangler.
 *
 * Copyright (C) 2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 *
 * See http://mentorembedded.github.io/cxx-abi/abi.html#mangling
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "utils.h"

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

static char dd_consume_n(struct demangle_data *dd, int n)
{
	char c = dd_curr(dd);

	if (dd->pos + n > dd->len)
		return 0;

	dd->pos += n;
	return c;
}

static char dd_consume(struct demangle_data *dd)
{
	return dd_consume_n(dd, 1);
}

#define DD_DEBUG(dd, exp, inc)						\
({	dd->func = __func__; dd->line = __LINE__ - 1; dd->pos += inc;	\
	dd->expected = exp;						\
	return -1;							\
})

#define DD_DEBUG_CONSUME(dd, exp_c)					\
({	if (dd_consume(dd) != exp_c) {					\
		dd->func = __func__; dd->line = __LINE__; dd->pos--;	\
		dd->expected = dd_expbuf; dd_expbuf[0] = exp_c;		\
		return -1;						\
	}								\
})

static void dd_debug_print(struct demangle_data *dd)
{
	const char *expected = dd->expected;

	if (expected == NULL) {
		if (dd_eof(dd))
			expected = "more input";
		else
			expected = "unknown input";
	}

	pr_dbg("demangle failed:\n%s\n%*c\n%s:%d: \"%s\" expected\n",
	       dd->old, dd->pos + 1, '^', dd->func, dd->line, expected);
}

static const struct {
	char op[2];
	char *name;
} ops[] = {
	{ { 'n','w' }, "new" },
	{ { 'n','a' }, "new[]" },
	{ { 'd','l' }, "delete" },
	{ { 'd','a' }, "delete[]" },
	{ { 'p','s' }, "+" }, /* unary */
	{ { 'n','g' }, "-" }, /* unary */
	{ { 'a','d' }, "&" }, /* unary */
	{ { 'd','e' }, "*" }, /* unary */
	{ { 'c','o' }, "~" },
	{ { 'p','l' }, "+" },
	{ { 'm','i' }, "-" },
	{ { 'm','l' }, "*" },
	{ { 'd','v' }, "/" },
	{ { 'r','m' }, "%" },
	{ { 'a','n' }, "&" },
	{ { 'o','r' }, "|" },
	{ { 'e','o' }, "^" },
	{ { 'a','S' }, "=" },
	{ { 'p','L' }, "+=" },
	{ { 'm','I' }, "-=" },
	{ { 'm','L' }, "*=" },
	{ { 'd','V' }, "/=" },
	{ { 'r','M' }, "%=" },
	{ { 'a','N' }, "&=" },
	{ { 'o','R' }, "|=" },
	{ { 'e','O' }, "^=" },
	{ { 'l','s' }, "<<" },
	{ { 'r','s' }, ">>" },
	{ { 'l','S' }, "<<=" },
	{ { 'r','S' }, ">>=" },
	{ { 'e','q' }, "==" },
	{ { 'n','e' }, "!=" },
	{ { 'l','t' }, "<" },
	{ { 'g','t' }, ">" },
	{ { 'l','e' }, "<=" },
	{ { 'g','e' }, ">=" },
	{ { 'n','t' }, "!" },
	{ { 'a','a' }, "&&" },
	{ { 'o','o' }, "||" },
	{ { 'p','p' }, "++" },
	{ { 'm','m' }, "--" },
	{ { 'c','m' }, "," },
	{ { 'p','m' }, "->*" },
	{ { 'p','t' }, "->" },
	{ { 'c','l' }, "()" },
	{ { 'i','x' }, "[]" },
	{ { 'q','u' }, "?" },
	{ { 'c','v' }, "(cast)" },
	{ { 'l','i' }, "\"\"" },
};

static const struct {
	char code;
	char *name;
} types[] = {
	{ 'v', "void" },
	{ 'w', "wchar_t" },
	{ 'b', "bool" },
	{ 'c', "char" },
	{ 'a', "signed char" },
	{ 'h', "unsigned char" },
	{ 's', "short" },
	{ 't', "unsigned short" },
	{ 'i', "int" },
	{ 'j', "unsigned int" },
	{ 'l', "long" },
	{ 'm', "unsigned long" },
	{ 'x', "long long" },
	{ 'y', "unsigned long long" },
	{ 'n', "__int128" },
	{ '0', "unsigned __int128" },
	{ 'f', "float" },
	{ 'd', "double" },
	{ 'e', "long double" },
	{ 'g', "__float128" },
	{ 'z', "..." },
};

static const struct {
	char *code;
	char *name;
} exprs[] = {
	{ "pp_", "++" },
	{ "mm_", "--" },
	{ "cl",  "call()" },
	{ "cv",  "(cast)" },
	{ "ti",  "initializer" },
	{ "il",  "initializer" },
	{ "nw",  "new() <type>" },
	{ "na",  "new[]() <type>" },
	{ "dl",  "delete" },
	{ "da",  "delete[]" },
	{ "dc",  "dynamic_cast<type>" },
	{ "sc",  "static_cast<type>" },
	{ "cc",  "const_cast<type>" },
	{ "rc",  "reinterprete_cast<type>" },
	{ "ti",  "typeid" },
	{ "te",  "typeid()" },
	{ "st",  "sizeof" },
	{ "sz",  "sizeof()" },
	{ "at",  "alignof" },
	{ "az",  "alignof()" },
	{ "nx",  "noexcept()" },
	{ "dt",  "<expr>.<name>" },
	{ "pt",  "<expr>-><name>" },
	{ "ds",  "<expr>.*<expr>" },
	{ "sZ",  "sizeof<T>" },
	{ "sP",  "sizeof<T>" },
	{ "sp",  "pack expansion" },
	{ "tw",  "throw()" },
	{ "tr",  "throw" },
	{ "gs",  ":: (global scope)" },
	{ "sr",  "unresolved name" },
	{ "srN", "unresolved name" },
	{ "on",  "operator name" },
	{ "dn",  "destructor name" },
	{ "pi",  "initializer" },
};

static const struct {
	char code;
	char *name;
} std_abbrevs[] = {
	{ 't', "::std" },
	{ 'a', "::std::allocator" },
	{ 'b', "::std::basic_string" },
	{ 's', "::std::basic_string<>" },
	{ 'i', "::std::basic_istream" },
	{ 'o', "::std::basic_ostream" },
	{ 'd', "::std::basic_iostream" },
};

static int dd_encoding(struct demangle_data *dd);
static int dd_name(struct demangle_data *dd);
static int dd_source_name(struct demangle_data *dd);
static int dd_operator_name(struct demangle_data *dd);
static int dd_nested_name(struct demangle_data *dd);
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

	strncpy(&dd->new[dd->newpos], str, size);
	dd->newpos += size;
	dd->new[dd->newpos] = '\0';

	return 0;
}

static int dd_append(struct demangle_data *dd, char *str)
{
	return dd_append_len(dd, str, strlen(str));
}

static int dd_number(struct demangle_data *dd)
{
	char *str = &dd->old[dd->pos];
	char *end;
	int num;

	if (!isdigit(*str))
		DD_DEBUG(dd, "digit", 0);

	num = strtoul(str, &end, 0);
	dd->pos += end - str;

	return num;
}

static int dd_seq_id(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	/* just skip for now */
	while (isdigit(c) || isupper(c))
		c = dd->old[++dd->pos];
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
		DD_DEBUG_CONSUME(dd, '_');
		return 0;
	}
	if (c == 'v') {
		dd_consume(dd);
		if (dd_number(dd) < 0)
			return -1;
		DD_DEBUG_CONSUME(dd, '_');
		if (dd_number(dd) < 0)
			return -1;
		DD_DEBUG_CONSUME(dd, '_');
		return 0;
	}
	return -1;
}

static int dd_qualifier(struct demangle_data *dd)
{
	char c = dd_curr(dd);
	char qual[] = "rVKRO";

	/* qualifiers are optional and we ignore them */
	if (strchr(qual, c))
		dd_consume(dd);

	return 0;
}

static int dd_initializer(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = dd_consume(dd);

	if (c0 != 'p' || c1 != 'i')
		DD_DEBUG(dd, "pi", -2);

	dd->level++;
	while (dd_curr(dd) != 'E') {
		if (dd_expression(dd) < 0)
			return -1;
	}
	DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
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
			dd_consume(dd);
			if (dd->type == 0)
				dd_append(dd, std_abbrevs[i].name);
			return 0;
		}
	}

	dd_seq_id(dd);
	DD_DEBUG_CONSUME(dd, '_');
	return 0;
}

static int dd_function_param(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = dd_consume(dd);

	if (dd_eof(dd))
		return -1;

	if (c0 != 'F' || (c1 != 'p' && c1 != 'L'))
		DD_DEBUG(dd, "Fp or FL", -2);

	if (isdigit(dd_curr(dd))) {
		dd_number(dd);
		DD_DEBUG_CONSUME(dd, 'p');
	}

	dd_qualifier(dd);

	if (isdigit(dd_curr(dd)))
		dd_number(dd);
	DD_DEBUG_CONSUME(dd, '_');
	return 0;
}

static int dd_template_param(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'T');

	dd_number(dd);

	DD_DEBUG_CONSUME(dd, '_');
	return 0;
}

static int dd_template_arg(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (c == 'X') {
		dd_consume(dd);

		dd->level++;
		dd_expression(dd);
		DD_DEBUG_CONSUME(dd, 'E');
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
		DD_DEBUG_CONSUME(dd, 'E');
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

	dd->type++;
	dd->level++;

	while (dd_curr(dd) != 'E') {
		if (dd_template_arg(dd) < 0)
			return -1;
	}
	DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
	dd->type--;
	return 0;
}

static int dd_simple_id(struct demangle_data *dd)
{
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

	if (c == 'T')
		return dd_template_param(dd);
	if (c == 'D')
		return dd_decltype(dd);
	if (c == 'S')
		return dd_substitution(dd);
	return -1;
}

static int dd_destructor_name(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	if (isdigit(c))
		return dd_source_name(dd);
	return dd_unresolved_type(dd);
}

static int dd_base_unresolved_name(struct demangle_data *dd)
{
	char c0 = dd_curr(dd);
	char c1 = dd_peek(dd, 1);

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

	if (c0 == 'g' && c1 == 's') {
		dd_consume_n(dd, 2);
		c0 = dd_curr(dd);
		c1 = dd_peek(dd, 1);
	}

	if (c0 == 's' && c1 == 'r') {
		dd_consume_n(dd, 2);
		if (dd_curr(dd) == 'N')
			dd_consume(dd);

		c0 = dd_curr(dd);
		c1 = dd_peek(dd, 1);
		if (c0 == 'T' || c0 == 'D' || c0 == 'S') {
			if (dd_unresolved_type(dd) < 0)
				return -1;
		}

		while (isdigit(c0)) {
			if (dd_simple_id(dd) < 0)
				return -1;
			c0 = dd_curr(dd);
			c1 = dd_peek(dd, 1);
		}

		if (c0 == 'E') {
			dd_consume(dd);
			return dd_base_unresolved_name(dd);
		}
		if ((c0 == 'o' || c0 == 'd') && c1 == 'n')
			return dd_base_unresolved_name(dd);
		return 0;
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
		dd_consume_n(dd, 2);

		if (dd_encoding(dd) < 0)
			return -1;
		DD_DEBUG_CONSUME(dd, 'E');

		dd->level--;
		return 0;
	}

	dd_type(dd);
	dd_number(dd);
	if (dd_curr(dd) == '_') {
		dd_consume(dd);
		dd_number(dd);
	}

	DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
	dd->type--;
	return 0;
}

static int dd_expr_list(struct demangle_data *dd)
{
	char c = dd_curr(dd);

	dd->level++;
	while (c != 'E' && c != '_') {
		if (dd_expression(dd) < 0)
			return -1;
		c = dd_curr(dd);
	}
	dd_consume(dd);
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
		"ps", "ng", "ad", "de", "pp_", "mm_", "gs", "dl", "da",
		"te", "sz", "az", "nx", "sp", "tw",
	};

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
		DD_DEBUG_CONSUME(dd, 'E');
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
		dd_consume(dd);

	dd->type++;
	dd->level++;

	c = dd_curr(dd);
	while (c != 'E') {
		int old_pos = dd->pos;

		if (c == 'R' || c == 'O')
			dd_qualifier(dd);

		if (dd_type(dd) < 0) {
			dd->pos = old_pos;
			break;
		}

		c = dd_curr(dd);
	}

	if (c == 'R' || c == 'O')
		dd_qualifier(dd);

	DD_DEBUG_CONSUME(dd, 'E');

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
	else
		dd_expression(dd); /* optional */

	DD_DEBUG_CONSUME(dd, '_');

	return dd_type(dd);
}

static int dd_ptr_to_member_type(struct demangle_data *dd)
{
	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'M');

	if (dd_type(dd) < 0)  /* class */
		return -1;
	return dd_type(dd);   /* member */
}

static int dd_decltype(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = dd_consume(dd);

	if (dd_eof(dd))
		return -1;

	if (c0 != 'D' || (c1 != 'T' && c1 != 't'))
		DD_DEBUG(dd, "DT or Dt", -2);

	dd->type++;
	dd->level++;

	dd_expression(dd);

	DD_DEBUG_CONSUME(dd, 'E');

	dd->level--;
	dd->type--;
	return 0;
}

static int dd_type(struct demangle_data *dd)
{
	unsigned i;
	char cv_qual[] = "rVK";
	char prefix[] = "PROCG";
	char D_types[] = "defhisacn";
	char scue[] = "sue"; /* struct, class, union, enum */
	int done = 0;
	int ret = -1;

	/* ignore type names */
	dd->type++;

	while (!done) {
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
			else if (c == 't' || c == 'T')
				ret = dd_decltype(dd);
			done = 1;
		}
		else if (c == 'S') {
			ret = dd_substitution(dd);
			if (dd_curr(dd) == 'I')
				ret = dd_template_args(dd);
			done = 1;
		}
		else if (c == 'N') {
			ret = dd_nested_name(dd);
			done = 1;
		}
		else {
			/* builtin types */
			for (i = 0; i < ARRAY_SIZE(types); i++) {
				if (c == types[i].code) {
					dd_consume(dd);
					ret = 0;
					break;
				}
			}
			if (c == 'u')
				dd_consume(dd);
			if (isdigit(dd_curr(dd)))
				ret = dd_source_name(dd);
			done = 1;
		}
	}

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
		dd_consume(dd);
		if (dd_number(dd) < 0)
			return -1;
		DD_DEBUG_CONSUME(dd, '_');
	}
	return 0;
}

static int dd_special_name(struct demangle_data *dd)
{
	char c0 = dd_curr(dd);
	char c1 = dd_peek(dd, 1);
	char T_type[] = "VTIS";

	if (dd_eof(dd))
		return -1;

	if (c0 == 'T') {
		if (strchr(T_type, c1)) {
			dd_consume_n(dd, 2);
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
	}
	if (c0 == 'G') {
		if (c1 == 'V') {
			dd_consume_n(dd, 2);
			return dd_name(dd);
		}
		if (c1 == 'R') {
			dd_consume_n(dd, 2);
			if (dd_name(dd) < 0)
				return -1;

			if (dd_curr(dd) != '_')
				dd_seq_id(dd);
			DD_DEBUG_CONSUME(dd, '_');
			return 0;
		}
	}

	DD_DEBUG(dd, "valid special name", 0);
	return 0;
}

static int dd_ctor_dtor_name(struct demangle_data *dd)
{
	char c0 = dd_consume(dd);
	char c1 = dd_consume(dd);
	char *pos;
	int len;

	if (dd_eof(dd))
		return -1;

	if ((c0 != 'C' && c0 != 'D') || !isdigit(c1))
		DD_DEBUG(dd, "C[0-3] or D[0-3]", -2);

	if (dd->type)
		return 0;

	/* repeat last name after '::' */
	pos = strrchr(dd->new, ':');
	if (pos == NULL)
		pos = dd->new;
	else
		pos++;

	len = strlen(pos);

	if (c0 == 'C')
		dd_append(dd, "::");
	else
		dd_append(dd, "::~");

	dd_append_len(dd, pos, len);
	return 0;
}

static int dd_operator_name(struct demangle_data *dd)
{
	unsigned i;
	char c0 = dd_consume(dd);
	char c1 = dd_consume(dd);

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
			if (dd->newpos)
				dd_append(dd, "::");
			dd_append(dd, "operator ");
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

	if (num < 0)
		return -1;

	if (dd_eof(dd) || dd->pos + num > dd->len)
		DD_DEBUG(dd, "shorter name", 0);

	if (dd->type)
		goto out;

	if (dd->newpos)
		dd_append(dd, "::");
	dd_append_len(dd, &dd->old[dd->pos], num);

out:
	dd_consume_n(dd, num);
	return 0;
}

static int dd_unqualified_name(struct demangle_data *dd)
{
	char c0 = dd_curr(dd);
	char c1 = dd_peek(dd, 1);

	if (dd_eof(dd))
		return -1;

	if ((c0 == 'C' || c0 == 'D') && isdigit(c1))
		return dd_ctor_dtor_name(dd);
	if (c0 == 'U') {
		dd->type++;

		if (c1 == 't') {
			/* unnamed type name */
			dd_consume_n(dd, 2);
			if (dd_number(dd) < 0)
				return -1;
			DD_DEBUG_CONSUME(dd, '_');
		}
		else if (c1 == 'I') {
			/* closure type name */
			dd_consume_n(dd, 2);

			dd->level++;
			while (dd_curr(dd) != 'E') {
				if (dd_type(dd) < 0)
					break;
			}
			DD_DEBUG_CONSUME(dd, 'E');
			dd->level--;

			if (dd_curr(dd) != '_') {
				if (dd_number(dd) < 0)
					return -1;
			}
			DD_DEBUG_CONSUME(dd, '_');
		}
		else {
			return -1;
		}

		dd->type--;
		return 0;
	}
	if (islower(c0))
		return dd_operator_name(dd);

	return dd_source_name(dd);
}

static int dd_nested_name(struct demangle_data *dd)
{
	char qual[] = "rVKRO";

	if (dd_eof(dd))
		return -1;

	DD_DEBUG_CONSUME(dd, 'N');
	dd->level++;

	while (dd_curr(dd) != 'E') {
		char c0 = dd_curr(dd);
		char c1 = dd_peek(dd, 1);

		if (((c0 == 'C' || c0 == 'D') && isdigit(c1)) ||
		    c0 == 'U' || islower(c0) || isdigit(c0))
			dd_unqualified_name(dd);
		else if (c0 == 'T')
			dd_template_param(dd);
		else if (c0 == 'I')
			dd_template_args(dd);
		else if (c0 == 'S')
			dd_substitution(dd);
		else if (c0 == 'D' && (c1 == 'T' || c1 == 't'))
			dd_decltype(dd);
		else if (c0 == 'M')
			dd_consume(dd);  /* assumed data-member-prefix */
		else if (c0 == 'L')
			dd_consume(dd);  /* local-source-name ? */
		else if (strchr(qual, c0))
			dd_qualifier(dd);
		else
			break;
	}

	DD_DEBUG_CONSUME(dd, 'E');
	dd->level--;

	return 0;
}

static int dd_local_name(struct demangle_data *dd)
{
	char c = dd_consume(dd);

	if (dd_eof(dd))
		return -1;

	if (c != 'Z')
		return -1;

	dd->level++;
	dd_encoding(dd);
	DD_DEBUG_CONSUME(dd, 'E');
	dd->level--;

	c = dd_curr(dd);
	if (c == 'd') {
		dd_consume(dd);
		if (dd_number(dd) < 0)
			return -1;
		DD_DEBUG_CONSUME(dd, '_');
		if (dd_name(dd) < 0)
			return -1;
		return 0;
	}

	if (c == 's')
		dd_consume(dd);
	else
		dd_name(dd);

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
		char c1 = dd_peek(dd, 1);

		if (c1 == 't') {
			dd_consume_n(dd, 2);

			if (!dd->type)
				dd_append(dd, "::std");
			/* fall through to dd_unqualified_name() */
		} else if (c1 == '_' || isdigit(c1) || isupper(c1)) {
			dd_substitution(dd);

			if (dd_curr(dd) == 'I')
				return dd_template_args(dd);
			return 0;
		} else {
			return -1;
		}
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
	char c = dd_curr(dd);

	if (dd_eof(dd))
		return -1;

	if (c == 'T' || c == 'G')
		return dd_special_name(dd);

	ret = dd_name(dd);
	if (ret < 0)
		return ret;

	while (!dd_eof(dd)) {
		if (dd_type(dd) < 0)
			break;
	}
	return 0;
}

char *demangle(char *str)
{
	struct demangle_data dd = {
		.old = str,
		.len = strlen(str),
	};

	if (str[0] != '_' || str[1] != 'Z')
		return str;

	dd.pos = 2;
	dd.new = xzalloc(0);

	if (dd_encoding(&dd) < 0 || !dd_eof(&dd) || dd.level != 0) {
		dd_debug_print(&dd);
		free(dd.new);
		return str;
	}

	/* caller should free it */
	return dd.new;
}
