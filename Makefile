VERSION := 0.8.1

# Makefiles suck: This macro sets a default value of $(2) for the
# variable named by $(1), unless the variable has been set by
# environment or command line. This is necessary for CC and AR
# because make sets default values, so the simpler ?= approach
# won't work as expected.
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

# Allow setting CC and AR and LD, or setting CROSS_COMPILE as a prefix.
$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,AR,$(CROSS_COMPILE)ar)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

uname_M := $(shell uname -m 2>/dev/null || echo not)

ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/arm.*/arm/ )
ifeq ($(ARCH),x86_64)
  ifneq ($(findstring m32,$(CFLAGS)),)
    override ARCH := i386
  endif
endif

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

ifneq ($(wildcard $(objdir)/.config),)
  include $(objdir)/.config
endif

RM = rm -f
INSTALL = install

export ARCH CC AR LD RM srcdir objdir LDFLAGS

COMMON_CFLAGS := -std=gnu99 -O2 -g -D_GNU_SOURCE $(CFLAGS) $(CPPFLAGS)
COMMON_CFLAGS +=  -iquote $(srcdir) -iquote $(objdir) -iquote $(srcdir)/arch/$(ARCH)
#CFLAGS-DEBUG = -g -D_GNU_SOURCE $(CFLAGS_$@)
COMMON_LDFLAGS := -lelf -lrt -ldl -pthread $(LDFLAGS)

COMMON_CFLAGS += -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers

#
# Note that the plain CFLAGS and LDFLAGS can be changed
# by config/Makefile later but *_*FLAGS can not.
#
UFTRACE_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@) $(CFLAGS_uftrace)
TRACEEVENT_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@) $(CFLAGS_traceevent)
LIB_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@) $(CFLAGS_lib) -fPIC -fvisibility=hidden

UFTRACE_LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@) $(LDFLAGS_uftrace)
LIB_LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@) $(LDFLAGS_lib)

export UFTRACE_CFLAGS LIB_CFLAGS

VERSION_GIT := $(shell git describe --tags 2> /dev/null || echo v$(VERSION))

all:

ifneq ($(wildcard $(srcdir)/check-deps/check-tstamp),)
  include $(srcdir)/check-deps/Makefile.check
endif

include $(srcdir)/Makefile.include


LIBMCOUNT_TARGETS := libmcount/libmcount.so libmcount/libmcount-fast.so
LIBMCOUNT_TARGETS += libmcount/libmcount-single.so libmcount/libmcount-fast-single.so

_TARGETS := uftrace libtraceevent/libtraceevent.a
_TARGETS += $(LIBMCOUNT_TARGETS) libmcount/libmcount-nop.so
TARGETS  := $(patsubst %,$(objdir)/%,$(_TARGETS))

UFTRACE_SRCS := $(srcdir)/uftrace.c $(wildcard $(srcdir)/cmd-*.c $(srcdir)/utils/*.c)
UFTRACE_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.o,$(UFTRACE_SRCS))

UFTRACE_ARCH_OBJS := $(objdir)/arch/$(ARCH)/uftrace.o

UFTRACE_HDRS := $(filter-out $(srcdir)/version.h,$(wildcard $(srcdir)/*.h $(srcdir)/utils/*.h))
UFTRACE_HDRS += $(srcdir)/libmcount/mcount.h $(wildcard $(srcdir)/arch/$(ARCH)/*.h)

LIBMCOUNT_SRCS := $(filter-out %-nop.c,$(wildcard $(srcdir)/libmcount/*.c))
LIBMCOUNT_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_SRCS))
LIBMCOUNT_FAST_OBJS := $(patsubst $(objdir)/%.op,$(objdir)/%-fast.op,$(LIBMCOUNT_OBJS))
LIBMCOUNT_SINGLE_OBJS := $(patsubst $(objdir)/%.op,$(objdir)/%-single.op,$(LIBMCOUNT_OBJS))
LIBMCOUNT_FAST_SINGLE_OBJS := $(patsubst $(objdir)/%.op,$(objdir)/%-fast-single.op,$(LIBMCOUNT_OBJS))

LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/symbol.c $(srcdir)/utils/debug.c
LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/rbtree.c $(srcdir)/utils/filter.c
LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/demangle.c $(srcdir)/utils/utils.c
LIBMCOUNT_UTILS_SRCS += $(srcdir)/utils/script.c $(srcdir)/utils/script-python.c
LIBMCOUNT_UTILS_OBJS := $(patsubst $(srcdir)/utils/%.c,$(objdir)/libmcount/%.op,$(LIBMCOUNT_UTILS_SRCS))

LIBMCOUNT_NOP_SRCS := $(srcdir)/libmcount/mcount-nop.c
LIBMCOUNT_NOP_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_NOP_SRCS))

LIBMCOUNT_ARCH_OBJS := $(objdir)/arch/$(ARCH)/mcount-entry.op

COMMON_DEPS := $(objdir)/.config $(UFTRACE_HDRS)
LIBMCOUNT_DEPS := $(COMMON_DEPS) $(srcdir)/libmcount/internal.h

CFLAGS_$(objdir)/mcount.op = -pthread
CFLAGS_$(objdir)/cmd-record.o = -DINSTALL_LIB_PATH='"$(libdir)"'
CFLAGS_$(objdir)/cmd-live.o = -DINSTALL_LIB_PATH='"$(libdir)"'
LDFLAGS_$(objdir)/uftrace = -L$(objdir)/libtraceevent -ltraceevent -ldl

LIBMCOUNT_FAST_CFLAGS := -DDISABLE_MCOUNT_FILTER
LIBMCOUNT_SINGLE_CFLAGS := -DSINGLE_THREAD
LIBMCOUNT_FAST_SINGLE_CFLAGS := -DDISABLE_MCOUNT_FILTER -DSINGLE_THREAD

CFLAGS_$(objdir)/utils/demangle.o  = -Wno-unused-value
CFLAGS_$(objdir)/utils/demangle.op = -Wno-unused-value

MAKEFLAGS = --no-print-directory


all: $(objdir)/.config $(TARGETS)

$(objdir)/.config: $(srcdir)/configure $(srcdir)/check-deps/Makefile
	$(QUIET_GEN)$(srcdir)/configure -p -o $@ $(MAKEOVERRIDES)
	@$(MAKE) -C $(objdir)
# The above recursive make will handle all build procedure with
# updated dependency.  So just abort the current build.
	$(error)

config: $(srcdir)/configure
	$(QUIET_GEN)$(srcdir)/configure -o $(objdir)/.config $(MAKEOVERRIDES)

$(LIBMCOUNT_UTILS_OBJS): $(objdir)/libmcount/%.op: $(srcdir)/utils/%.c $(LIBMCOUNT_DEPS)
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

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

$(filter-out $(objdir)/uftrace.o,$(UFTRACE_OBJS)): $(objdir)/%.o: $(srcdir)/%.c $(COMMON_DEPS)
	$(QUIET_CC)$(CC) $(UFTRACE_CFLAGS) -c -o $@ $<

$(objdir)/version.h: PHONY
	@$(srcdir)/misc/version.sh $@ $(VERSION_GIT)

$(objdir)/uftrace: $(UFTRACE_OBJS) $(UFTRACE_ARCH_OBJS) $(objdir)/libtraceevent/libtraceevent.a
	$(QUIET_LINK)$(CC) $(UFTRACE_CFLAGS) -o $@ $(UFTRACE_OBJS) $(UFTRACE_ARCH_OBJS) $(UFTRACE_LDFLAGS)

install: all
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(etcdir)/bash_completion.d
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
	$(Q)$(RM) $(DESTDIR)$(libdir)/libmcount{,-nop,-fast,-single,-fast-single}.so
	$(call QUIET_UNINSTALL, bash-completion)
	$(Q)$(RM) $(DESTDIR)$(etcdir)/bash_completion.d/uftrace
	@$(MAKE) -sC $(srcdir)/doc uninstall DESTDIR=$(DESTDIR)$(mandir)

test: all
	@$(MAKE) -C $(srcdir)/tests TESTARG="$(TESTARG)" test

dist:
	@git archive --prefix=uftrace-$(VERSION)/ $(VERSION_GIT) -o $(objdir)/uftrace-$(VERSION).tar
	@tar rf $(objdir)/uftrace-$(VERSION).tar --transform="s|^|uftrace-$(VERSION)/|" $(objdir)/version.h
	@gzip $(objdir)/uftrace-$(VERSION).tar

doc:
	@$(MAKE) -C $(srcdir)/doc

clean:
	$(call QUIET_CLEAN, uftrace)
	$(Q)$(RM) $(objdir)/*.o $(objdir)/*.op $(objdir)/*.so $(objdir)/*.a
	$(Q)$(RM) $(objdir)/utils/*.o $(objdir)/utils/*.op $(objdir)/libmcount/*.op
	$(Q)$(RM) $(objdir)/gmon.out $(srcdir)/scripts/*.pyc $(TARGETS)
	$(Q)$(RM) $(objdir)/uftrace-*.tar.gz $(objdir)/version.h
	@$(MAKE) -sC $(srcdir)/arch/$(ARCH) clean
	@$(MAKE) -sC $(srcdir)/tests ARCH=$(ARCH) clean
	@$(MAKE) -sC $(srcdir)/doc clean
	@$(MAKE) -sC $(srcdir)/libtraceevent clean

ctags:
	@find . -name "*\.[chS]" -o -path ./tests -prune -o -path ./check-deps -prune \
		| xargs ctags --regex-asm='/^(GLOBAL|ENTRY|END)\(([^)]*)\).*/\2/'

.PHONY: all config clean test dist doc ctags PHONY
