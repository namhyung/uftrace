VERSION := 0.9.1

prefix ?= /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib
etcdir = $(prefix)/etc
mandir = $(prefix)/share/man

srcdir = $(CURDIR)
# set objdir to $(O) by default (if any)
ifeq ($(objdir),)
    ifneq ($(O),)
        objdir = $(O)
    else
        objdir = $(CURDIR)
    endif
endif

include $(srcdir)/Makefile.include

ifneq ($(wildcard $(objdir)/.config),)
  include $(objdir)/.config
endif

#
# Note that the plain CFLAGS and LDFLAGS can be changed
# by config/Makefile later but *_*FLAGS can not.
#
UFTRACE_CFLAGS     = $(COMMON_CFLAGS) $(CFLAGS_$@) $(CFLAGS_uftrace)
TRACEEVENT_CFLAGS  = $(COMMON_CFLAGS) $(CFLAGS_$@) $(CFLAGS_traceevent)
TEST_CFLAGS        = $(COMMON_CFLAGS) -DUNIT_TEST

UFTRACE_LDFLAGS    = $(COMMON_LDFLAGS) $(LDFLAGS_$@) $(LDFLAGS_uftrace)
TEST_LDFLAGS       = $(COMMON_LDFLAGS) -L$(objdir)/libtraceevent -ltraceevent

ifeq ($(TRACE), 1)
  UFTRACE_CFLAGS    += -pg -fno-omit-frame-pointer
  TRACEEVENT_CFLAGS += -pg -fno-omit-frame-pointer
  TEST_CFLAGS       += -pg -fno-omit-frame-pointer
  # cannot add -pg to LIB_CFLAGS because mcount() is not reentrant
endif

ifeq ($(COVERAGE), 1)
  TEST_CFLAGS   += -O0 -g --coverage -U_FORTIFY_SOURCE
endif

ifeq ($(ASAN), 1)
  UFTRACE_CFLAGS    += -O0 -g -fsanitize=address
  DEMANGLER_CFLAGS  += -O0 -g -fsanitize=address
  SYMBOLS_CFLAGS    += -O0 -g -fsanitize=address
  TRACEEVENT_CFLAGS += -O0 -g -fsanitize=address
  TEST_CFLAGS       += -O0 -g -fsanitize=address
endif

export srcdir objdir UFTRACE_CFLAGS TEST_CFLAGS TEST_LDFLAGS

config: $(objdir)/.config

$(objdir)/.config: $(srcdir)/configure $(srcdir)/check-deps/Makefile
	$(QUIET_GEN)$(srcdir)/configure -p -o $@ $(MAKEOVERRIDES)

dependency-include:

ifneq ($(wildcard $(srcdir)/check-deps/check-tstamp),)
  include $(srcdir)/check-deps/Makefile.check
endif

prebuild:

LIBMCOUNT_TARGETS := libmcount/libmcount.so libmcount/libmcount-fast.so
LIBMCOUNT_TARGETS += libmcount/libmcount-single.so libmcount/libmcount-fast-single.so

_TARGETS := uftrace libtraceevent/libtraceevent.a
_TARGETS += $(LIBMCOUNT_TARGETS) libmcount/libmcount-nop.so
TARGETS  := $(patsubst %,$(objdir)/%,$(_TARGETS))

UFTRACE_SRCS := $(srcdir)/uftrace.c $(wildcard $(srcdir)/cmds/*.c $(srcdir)/utils/*.c)
UFTRACE_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.o,$(UFTRACE_SRCS))
UFTRACE_OBJS_VERSION := $(objdir)/cmds/script.o $(objdir)/cmds/tui.o
UFTRACE_OBJS_VERSION += $(objdir)/cmds/dump.o $(objdir)/cmds/info.o
UFTRACE_ARCH_OBJS := $(objdir)/arch/$(ARCH)/uftrace.o
UFTRACE_HDRS := $(filter-out $(srcdir)/version.h,$(wildcard $(srcdir)/*.h $(srcdir)/utils/*.h))
UFTRACE_HDRS += $(srcdir)/libmcount/mcount.h $(wildcard $(srcdir)/arch/$(ARCH)/*.h)

LIBMCOUNT_SRCS := $(filter-out %-nop.c,$(wildcard $(srcdir)/libmcount/*.c))
LIBMCOUNT_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_SRCS))
LIBMCOUNT_FAST_OBJS := $(patsubst $(objdir)/%.op,$(objdir)/%-fast.op,$(LIBMCOUNT_OBJS))
LIBMCOUNT_SINGLE_OBJS := $(patsubst $(objdir)/%.op,$(objdir)/%-single.op,$(LIBMCOUNT_OBJS))
LIBMCOUNT_FAST_SINGLE_OBJS := $(patsubst $(objdir)/%.op,$(objdir)/%-fast-single.op,$(LIBMCOUNT_OBJS))

LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/debug.c $(srcdir)/utils/regs.c
LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/rbtree.c $(srcdir)/utils/filter.c
LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/demangle.c $(srcdir)/utils/utils.c
LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/script.c $(srcdir)/utils/script-python.c
LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/auto-args.c $(srcdir)/utils/dwarf.c
LIBMCOUNT_UTILS_SRCS += $(wildcard $(srcdir)/utils/symbol*.c)
LIBMCOUNT_UTILS_OBJS := $(patsubst $(srcdir)/utils/%.c,$(objdir)/libmcount/%.op,$(LIBMCOUNT_UTILS_SRCS))

LIBMCOUNT_NOP_SRCS := $(srcdir)/libmcount/mcount-nop.c
LIBMCOUNT_NOP_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_NOP_SRCS))

LIBMCOUNT_ARCH_OBJS := $(objdir)/arch/$(ARCH)/mcount-entry.op

COMMON_DEPS := $(objdir)/.config $(UFTRACE_HDRS)
LIBMCOUNT_DEPS := $(COMMON_DEPS) $(srcdir)/libmcount/internal.h

CFLAGS_$(objdir)/mcount.op = -pthread
CFLAGS_$(objdir)/cmds/record.o = -DINSTALL_LIB_PATH='"$(libdir)"'
CFLAGS_$(objdir)/cmds/live.o = -DINSTALL_LIB_PATH='"$(libdir)"'
LDFLAGS_$(objdir)/uftrace = -L$(objdir)/libtraceevent -ltraceevent -ldl

LIBMCOUNT_FAST_CFLAGS := -DDISABLE_MCOUNT_FILTER
LIBMCOUNT_SINGLE_CFLAGS := -DSINGLE_THREAD
LIBMCOUNT_FAST_SINGLE_CFLAGS := -DDISABLE_MCOUNT_FILTER -DSINGLE_THREAD

CFLAGS_$(objdir)/utils/demangle.o  = -Wno-unused-value
CFLAGS_$(objdir)/utils/demangle.op = -Wno-unused-value

MAKEFLAGS += --no-print-directory

build: $(TARGETS)

$(LIBMCOUNT_UTILS_OBJS): $(objdir)/libmcount/%.op: $(srcdir)/utils/%.c $(LIBMCOUNT_DEPS)
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(objdir)/libmcount/mcount.op: $(objdir)/version.h 

$(LIBMCOUNT_OBJS): $(objdir)/%.op: $(srcdir)/%.c $(LIBMCOUNT_DEPS)
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(LIBMCOUNT_FAST_OBJS): $(objdir)/%-fast.op: $(srcdir)/%.c $(LIBMCOUNT_DEPS)
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) $(LIBMCOUNT_FAST_CFLAGS) -c -o $@ $<

$(LIBMCOUNT_SINGLE_OBJS): $(objdir)/%-single.op: $(srcdir)/%.c $(LIBMCOUNT_DEPS)
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) $(LIBMCOUNT_SINGLE_CFLAGS) -c -o $@ $<

$(LIBMCOUNT_FAST_SINGLE_OBJS): $(objdir)/%-fast-single.op: $(srcdir)/%.c $(LIBMCOUNT_DEPS)
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) $(LIBMCOUNT_FAST_SINGLE_CFLAGS) -c -o $@ $<

$(LIBMCOUNT_NOP_OBJS): $(objdir)/%.op: $(srcdir)/%.c $(LIBMCOUNT_DEPS)
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(objdir)/libmcount/libmcount.so: $(LIBMCOUNT_OBJS) $(LIBMCOUNT_UTILS_OBJS) $(LIBMCOUNT_ARCH_OBJS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libmcount/libmcount-fast.so: $(LIBMCOUNT_FAST_OBJS) $(LIBMCOUNT_UTILS_OBJS) $(LIBMCOUNT_ARCH_OBJS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libmcount/libmcount-single.so: $(LIBMCOUNT_SINGLE_OBJS) $(LIBMCOUNT_UTILS_OBJS) $(LIBMCOUNT_ARCH_OBJS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libmcount/libmcount-fast-single.so: $(LIBMCOUNT_FAST_SINGLE_OBJS) $(LIBMCOUNT_UTILS_OBJS) $(LIBMCOUNT_ARCH_OBJS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libmcount/libmcount-nop.so: $(LIBMCOUNT_NOP_OBJS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(LIBMCOUNT_ARCH_OBJS): $(wildcard $(srcdir)/arch/$(ARCH)/*.[cS]) $(LIBMCOUNT_DEPS)
	@$(MAKE) -B -C $(srcdir)/arch/$(ARCH) $@

$(UFTRACE_ARCH_OBJS): $(wildcard $(srcdir)/arch/$(ARCH)/*.[cS]) $(COMMON_DEPS)
	@$(MAKE) -B -C $(srcdir)/arch/$(ARCH) $@

$(objdir)/libtraceevent/libtraceevent.a: $(wildcard $(srcdir)/libtraceevent/*.[ch]) $(objdir)/.config
	@$(MAKE) -C $(srcdir)/libtraceevent BUILD_SRC=$(srcdir)/libtraceevent BUILD_OUTPUT=$(objdir)/libtraceevent CONFIG_FLAGS="$(TRACEEVENT_CFLAGS)"

$(objdir)/uftrace.o: $(srcdir)/uftrace.c $(objdir)/version.h $(COMMON_DEPS)
	$(QUIET_CC)$(CC) $(UFTRACE_CFLAGS) -c -o $@ $<

$(filter-out $(objdir)/uftrace.o, $(UFTRACE_OBJS)): $(objdir)/%.o: $(srcdir)/%.c $(COMMON_DEPS)
	$(QUIET_CC)$(CC) $(UFTRACE_CFLAGS) -c -o $@ $<

$(objdir)/version.h: PHONY
	@$(srcdir)/misc/version.sh $@ $(VERSION_GIT) $(srcdir)

$(srcdir)/utils/auto-args.h: $(srcdir)/misc/prototypes.h $(srcdir)/misc/gen-autoargs.py
	$(QUIET_GEN)$(srcdir)/misc/gen-autoargs.py -i $< -o $@

$(objdir)/uftrace: $(UFTRACE_OBJS) $(UFTRACE_ARCH_OBJS) $(objdir)/libtraceevent/libtraceevent.a
	$(QUIET_LINK)$(CC) $(UFTRACE_CFLAGS) -o $@ $(UFTRACE_OBJS) $(UFTRACE_ARCH_OBJS) $(UFTRACE_LDFLAGS)


all:
	$(MAKE) config
	$(MAKE) dependency-check
	$(MAKE) dependency-include
	$(MAKE) prebuild
	$(MAKE) build
	$(MAKE) misc

misc:
	@$(MAKE) -C $(srcdir)/misc

install: all
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(etcdir)/bash_completion.d
ifneq ($(wildcard $(elfdir)/lib/libelf.so),)
ifeq ($(wildcard $(prefix)/lib/libelf.so),)
	# install libelf only when it's not in the install directory.
	$(call QUIET_INSTALL, libelf)
	$(Q)$(INSTALL) $(elfdir)/lib/libelf.so   $(DESTDIR)$(libdir)/libelf.so
endif
endif
	$(call QUIET_INSTALL, uftrace)
	$(Q)$(INSTALL) $(objdir)/uftrace         $(DESTDIR)$(bindir)/uftrace
	$(call QUIET_INSTALL, libmcount)
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount.so   $(DESTDIR)$(libdir)/libmcount.so
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount-nop.so $(DESTDIR)$(libdir)/libmcount-nop.so
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount-fast.so $(DESTDIR)$(libdir)/libmcount-fast.so
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount-single.so $(DESTDIR)$(libdir)/libmcount-single.so
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount-fast-single.so $(DESTDIR)$(libdir)/libmcount-fast-single.so
	$(call QUIET_INSTALL, bash-completion)
	$(Q)$(INSTALL) -m 644 $(srcdir)/misc/bash-completion.sh $(DESTDIR)$(etcdir)/bash_completion.d/uftrace
	@$(MAKE) -sC $(srcdir)/doc install DESTDIR=$(DESTDIR)$(mandir)
	@if [ `id -u` = 0 ]; then ldconfig $(DESTDIR)$(libdir) || echo "ldconfig failed"; fi

uninstall:
	$(call QUIET_UNINSTALL, uftrace)
	$(Q)$(RM) $(DESTDIR)$(bindir)/uftrace
	$(call QUIET_UNINSTALL, libmcount)
	$(Q)$(RM) $(DESTDIR)$(libdir)/libmcount.so
	$(call QUIET_UNINSTALL, libmcount-nop)
	$(Q)$(RM) $(DESTDIR)$(libdir)/libmcount-nop.so
	$(call QUIET_UNINSTALL, libmcount-fast)
	$(Q)$(RM) $(DESTDIR)$(libdir)/libmcount-fast.so
	$(call QUIET_UNINSTALL, libmcount-single)
	$(Q)$(RM) $(DESTDIR)$(libdir)/libmcount-single.so
	$(call QUIET_UNINSTALL, libmcount-fast-single)
	$(Q)$(RM) $(DESTDIR)$(libdir)/libmcount-fast-single.so
	$(call QUIET_UNINSTALL, bash-completion)
	$(Q)$(RM) $(DESTDIR)$(etcdir)/bash_completion.d/uftrace
	@$(MAKE) -sC $(srcdir)/doc uninstall DESTDIR=$(DESTDIR)$(mandir)

test: all
	@$(MAKE) -C $(srcdir)/tests TESTARG="$(TESTARG)" test

unittest: all
	@$(MAKE) -C $(srcdir)/tests TESTARG="$(TESTARG)" test_unit

runtest: all
	@$(MAKE) -C $(srcdir)/tests TESTARG="$(TESTARG)" test_run

dist:
	@git archive --prefix=uftrace-$(VERSION)/ $(VERSION_GIT) -o $(objdir)/uftrace-$(VERSION).tar
	@tar rf $(objdir)/uftrace-$(VERSION).tar --transform="s|^|uftrace-$(VERSION)/|" $(objdir)/version.h
	@gzip $(objdir)/uftrace-$(VERSION).tar

doc:
	@$(MAKE) -C $(srcdir)/doc

clean:
	$(call QUIET_CLEAN, uftrace)
	$(Q)$(RM) $(objdir)/*.o $(objdir)/*.op $(objdir)/*.so $(objdir)/*.a
	$(Q)$(RM) $(objdir)/cmds/*.o $(objdir)/utils/*.o $(objdir)/misc/*.o
	$(Q)$(RM) $(objdir)/utils/*.op $(objdir)/libmcount/*.op
	$(Q)$(RM) $(objdir)/gmon.out $(srcdir)/scripts/*.pyc $(TARGETS)
	$(Q)$(RM) $(objdir)/uftrace-*.tar.gz $(objdir)/version.h
	$(Q)find -name "*\.gcda" -o -name "*\.gcno" | xargs $(RM)
	$(Q)$(RM) coverage.info
	@$(MAKE) -sC $(srcdir)/arch/$(ARCH) clean
	@$(MAKE) -sC $(srcdir)/tests ARCH=$(ARCH) clean
	@$(MAKE) -sC $(srcdir)/doc clean
	@$(MAKE) -sC $(srcdir)/libtraceevent BUILD_SRC=$(srcdir)/libtraceevent BUILD_OUTPUT=$(objdir)/libtraceevent CONFIG_FLAGS="$(TRACEEVENT_CFLAGS)" clean
	@$(MAKE) -sC $(srcdir)/misc clean
	@$(MAKE) -sC $(srcdir)/check-deps check-clean

reset-coverage:
	$(Q)find -name "*\.gcda" | xargs $(RM)
	$(Q)$(RM) coverage.info

ctags:
	@find . -name "*\.[chS]" -o -path ./tests -prune -o -path ./check-deps -prune \
		| xargs ctags --regex-asm='/^(GLOBAL|ENTRY|END)\(([^)]*)\).*/\2/'

.PHONY: all config clean test dist doc misc ctags PHONY
