#include <ctype.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "filter"
#define PR_DOMAIN DBG_FILTER

#include "uftrace.h"
#include "utils/arch.h"
#include "utils/argspec.h"
#include "utils/filter.h"
#include "utils/utils.h"

static bool is_arm_machine(struct uftrace_filter_setting *setting)
{
	return setting->arch == UFT_CPU_ARM;
}

static int check_so_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	const char *soname = data;
	int so_used = 0;

	if (!strncmp(uftrace_basename(info->dlpi_name), soname, strlen(soname)))
		so_used = 1;

	return so_used;
}

/* check whether the given library name is in shared object list */
static int has_shared_object(const char *soname)
{
	static int so_used = -1;

	if (so_used != -1)
		return so_used;

	so_used = dl_iterate_phdr(check_so_cb, (void *)soname);

	return so_used;
}

/* argument_spec = arg1/i32,arg2/x64,... */
struct uftrace_arg_spec *parse_argspec(char *str, struct uftrace_filter_setting *setting)
{
	struct uftrace_arg_spec *arg;
	int fmt = ARG_FMT_AUTO;
	int size = setting->lp64 ? 8 : 4;
	int idx;
	int type;
	int bit;
	char *suffix;
	char *p;
	
	if (!strncmp(str, "arg", 3) && isdigit(str[3])) {
		idx = strtol(str + 3, &suffix, 0);
		type = ARG_TYPE_INDEX;
	}
	
	else if (!strncmp(str, "retval", 6)) {
		idx = RETVAL_IDX;
		type = ARG_TYPE_INDEX;
		suffix = str + 6;
	}
	else if (!strncmp(str, "fparg", 5) && isdigit(str[5])) {
		idx = strtol(str + 5, &suffix, 0);
		fmt = ARG_FMT_FLOAT;
		type = ARG_TYPE_FLOAT;
		size = sizeof(double);
	}
	else {
		pr_dbg("invalid argspec: %s\n", str);
		return NULL;
	}


	arg = xzalloc(sizeof(*arg));
	INIT_LIST_HEAD(&arg->list);


	if (suffix == NULL || *suffix == '\0')
		goto out;
	if (*suffix == '%')
		goto type;
	if (*suffix != '/')
		goto err;

	suffix++;

	switch (*suffix) {
	case 'd':
		fmt = ARG_FMT_AUTO;
		break;
	case 'i':  
		if (strncmp(suffix, "ip",2) == 0) {
			fmt = ARG_FMT_INT_PTR;
			suffix += 2;
			size = sizeof(int);
		}
		else{
			fmt = ARG_FMT_SINT;
		}
		break;
	case 'u':
		fmt = ARG_FMT_UINT;
		break;
	case 'x':
		fmt = ARG_FMT_HEX;
		break;
	case 'o':
		fmt = ARG_FMT_OCT;
		break;
	case 's':
		fmt = ARG_FMT_STR;
		break;
	case 'c':
		fmt = ARG_FMT_CHAR;
		size = sizeof(char);
		break;
	case 'f':
		fmt = ARG_FMT_FLOAT;
		type = ARG_TYPE_FLOAT;
		size = sizeof(double);
		break;
	case 'S':
		if (has_shared_object("libc++.so")) {
			static bool warned = false;
			if (!warned) {
				pr_warn("std::string display for libc++.so is "
					"not supported.\n");
				warned = true;
			}
			goto err;
		}
		fmt = ARG_FMT_STD_STRING;
		break;
	case 'p':
		fmt = ARG_FMT_PTR;
		break;
	case 'e':
		fmt = ARG_FMT_ENUM;
		if (suffix[1] != ':' || (!isalpha(suffix[2]) && suffix[2] != '_')) {
			pr_use("invalid enum spec: %s\n", suffix);
			goto err;
		}
		arg->type_name = xstrdup(&suffix[2]);

		p = strchr(arg->type_name, '%');
		if (p)
			*p = '\0';
		pr_dbg2("parsing argspec for enum: %s\n", arg->type_name);
		suffix += strlen(arg->type_name) + 2;
		goto type;
	case 't':
		/* struct/union/class passed-by-value */
		fmt = ARG_FMT_STRUCT;
		size = strtol(&suffix[1], &suffix, 0);
		arg->struct_reg_cnt = 0;
		
		if (*suffix == ':') {
			arg->type_name = xstrdup(&suffix[1]);
			//printf("2 -------------------------- type name %s, suffix: %s\n", arg->type_name, suffix); 
			// Detect pointer-to-struct case (pass-by-ref)
			char *ref = strstr(arg->type_name, "/&");
			if (ref) {
				*ref = '\0'; // Strip "/&" from type_name
				// Extract and store the address
				char *addr_str = ref + 2; // skip "/&"
				unsigned long long addr = strtoull(addr_str, NULL, 0);
				arg->resolved_struct = (struct resolved_struct_type *) (uintptr_t) addr;
				arg->type = ARG_TYPE_REG;
				arg->size = sizeof(void *);
				arg->is_ptr = 1;	
			}
			// Remove trailing register marker
			p = strchr(arg->type_name, '%');
			if (p)
				*p = '\0';			
			suffix += strlen(arg->type_name) + 1;
			
		}
	
		pr_dbg2("parsing argspec for struct: %s\n", arg->type_name ?: "(no name)");

		if (*suffix == '%') {
			if (!strncmp(suffix, "%stack+", 7))
				goto type;

			do {
				short reg;
				char *next = strchr(suffix, '+');

				if (next)
					*next = '\0';

				reg = arch_register_number(setting->arch, ++suffix);
				if (reg >= 0) {
					arg->struct_regs[arg->struct_reg_cnt++] = reg;
					arg->reg_idx = reg;
				}

				suffix = next;
			} while (suffix);

			if (arg->struct_reg_cnt)
				type = ARG_TYPE_REG;
		}
		goto out;
	default:
		if (fmt == ARG_FMT_FLOAT && isdigit(*suffix))
			goto size;
		pr_use("unsupported argument type: %s\n", str);
		goto err;
	}

	suffix++;
	if (*suffix == '\0')
		goto out;
	if (*suffix == '%')
		goto type;

size:
	bit = strtol(suffix, &suffix, 10);
	switch (bit) {
	case 8:
	case 16:
	case 32:
	case 64:
		size = bit / 8;
		break;
	case 80:
		if (fmt == ARG_FMT_FLOAT) {
			size = bit / 8;
			break;
		}
		/* fall through */
	default:
		pr_use("unsupported argument size: %s\n", str);
		goto err;
	}

type:
	if (*suffix == '%') {
		suffix++;

		if (!strncmp(suffix, "stack", 5)) {
			arg->stack_ofs = strtol(suffix + 5, NULL, 0);
			type = ARG_TYPE_STACK;
		}
		else {
			arg->reg_idx = arch_register_number(setting->arch, suffix);
			type = ARG_TYPE_REG;

			if (arg->reg_idx < 0) {
				pr_use("unknown register name: %s\n", str);
				goto err;
			}
		}
	}
	else if (*suffix != '\0')
		goto err;

out:
	/* it seems ARM falls back 'long double' to 'double' */
	if (fmt == ARG_FMT_FLOAT && size == 10 && is_arm_machine(setting))
		size = 8;

	arg->idx = idx;
	arg->fmt = fmt;
	arg->size = size;
	arg->type = type;
	return arg;

err:
	pr_dbg("argspec parse failed: %s\n", str);
	free_arg_spec(arg);
	return NULL;
}

void free_arg_spec(struct uftrace_arg_spec *arg)
{
	free(arg->type_name);
	free(arg);
}

#ifdef UNIT_TEST
TEST_CASE(argspec_parse_struct)
{
	char *str;
	struct uftrace_arg_spec *spec;
	struct uftrace_filter_setting setting = { .arch = UFT_CPU_X86_64 };

	/* parse_argspec might change the string, copy it */
	str = strdup("arg3/t16:mystruct%RDI+RSI");
	pr_dbg("parsing a struct passed by value: %s\n", str);

	spec = parse_argspec(str, &setting);
	TEST_NE(spec, NULL);
	TEST_EQ(spec->idx, 3);
	TEST_EQ(spec->fmt, ARG_FMT_STRUCT);
	TEST_EQ(spec->size, 16);
	TEST_EQ(spec->type, ARG_TYPE_REG);

	TEST_STREQ(spec->type_name, "mystruct");
	TEST_EQ(spec->struct_reg_cnt, 2);
	TEST_EQ(spec->struct_regs[0], UFT_X86_64_REG_RDI);
	TEST_EQ(spec->struct_regs[1], UFT_X86_64_REG_RSI);

	free_arg_spec(spec);
	free(str);
	return TEST_OK;
}
#endif /* UNIT_TEST */