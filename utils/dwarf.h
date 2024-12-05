#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "utils/filter.h"
#include "utils/rbtree.h"

struct uftrace_sym_info;
struct uftrace_module;

#ifdef HAVE_LIBDW
#include <elfutils/libdwfl.h>
extern Dwfl_Callbacks dwfl_callbacks;
#endif

struct uftrace_dbg_file {
	/* saved in uftrace_dbg_info.files */
	struct rb_node node;
	/* source file name */
	char *name;
};

/* we only keep the start location of symbol */
struct uftrace_dbg_loc {
	/* symbol for this location */
	struct uftrace_symbol *sym;
	/* filename info */
	struct uftrace_dbg_file *file;
	/* line number info */
	int line;
};

struct uftrace_dbg_info {
	/* opaque DWARF info pointer */
	void *dw;
	/* opaque pointer for DWARF frontend library */
	void *dwfl;
	/* start address in memory for this module */
	uint64_t offset;
	/* rb tree of arguments */
	struct rb_root args;
	/* rb tree of return values */
	struct rb_root rets;
	/* rb tree of enum tags/values */
	struct rb_root enums;
	/* rb tree of file info */
	struct rb_root files;
	/* array of location - same order as symbol */
	struct uftrace_dbg_loc *locs;
	/* number of debug location info */
	size_t nr_locs;
	/* number of actually used debug location info */
	size_t nr_locs_used;
	/* ELF file type - EXEC, REL, DYN */
	int file_type;
	/* whether it needs to parse argument info */
	bool needs_args;
	/* whether it's loaded already */
	bool loaded;
	/* name of common directory path for source files (can be %NULL) */
	char *base_dir;
};

extern void prepare_debug_info(struct uftrace_sym_info *sinfo, enum uftrace_pattern_type ptype,
			       char *argspec, char *retspec, bool auto_args, bool force);
extern void finish_debug_info(struct uftrace_sym_info *sinfo);
extern bool debug_info_has_argspec(struct uftrace_dbg_info *dinfo);
extern bool debug_info_has_location(struct uftrace_dbg_info *dinfo);
extern char *get_dwarf_argspec(struct uftrace_dbg_info *dinfo, char *name, unsigned long addr);
extern char *get_dwarf_retspec(struct uftrace_dbg_info *dinfo, char *name, unsigned long addr);
struct uftrace_dbg_loc *find_file_line(struct uftrace_sym_info *sinfo, uint64_t addr);
extern void save_debug_info(struct uftrace_sym_info *sinfo, const char *dirname);
extern void load_debug_info(struct uftrace_sym_info *sinfo, bool needs_srcline);
extern void save_debug_file(FILE *fp, char code, char *str, unsigned long val);
extern void load_module_debug_info(struct uftrace_module *mod, const char *dirname,
				   bool needs_srcline);

#endif /* UFTRACE_DWARF_H */
