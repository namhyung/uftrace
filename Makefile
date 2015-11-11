VERSION := 0.4

CC = $(CROSS_COMPILE)gcc
RM = rm -f
INSTALL = install

COMMON_CFLAGS := -O2 -g -D_GNU_SOURCE $(EXTRA_CFLAGS)
#CFLAGS-DEBUG = -g -D_GNU_SOURCE $(CFLAGS_$@)
COMMON_LDFLAGS := -lelf -lrt -pthread $(EXTRA_LDFLAGS)

COMMON_CFLAGS += -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers

#
# Note that the plain CFLAGS and LDFLAGS can be changed
# by config/Makefile later but LIB_*FLAGS are not.
#
CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@)
LIB_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@) -fPIC -fvisibility=hidden

LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@)
LIB_LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@)

prefix ?= /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib
mandir = $(prefix)/share/man

VERSION_GIT := $(shell git describe --tags 2> /dev/null || echo v$(VERSION))

# Check if bulid flags changed
BUILD_FLAGS := $(COMMON_CFLAGS) $(COMMON_LDFLAGS) $(prefix)
SAVED_FLAGS := $(shell cat FLAGS 2> /dev/null)

all:

uname_M := $(shell uname -m 2>/dev/null || echo not)

ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/arm.*/arm/ )
ifeq ($(ARCH),x86_64)
  ifneq ($(findstring m32,$(CFLAGS)),)
    override ARCH := i386
  endif
endif

CFLAGS_mcount.op = -pthread
CFLAGS_ftrace = -DINSTALL_LIB_PATH='"$(libdir)"' -I.
LDFLAGS_ftrace = libtraceevent/libtraceevent.a -ldl

include config/Makefile
include config/Makefile.include


TARGETS := ftrace libmcount/libmcount.so libmcount/libmcount-nop.so
TARGETS += libmcount/libmcount-fast.so libmcount/libmcount-single.so
TARGETS += libmcount/libmcount-fast-single.so libtraceevent/libtraceevent.a

FTRACE_SRCS  = ftrace.c cmd-record.c cmd-replay.c cmd-live.c cmd-report.c cmd-info.c
FTRACE_SRCS += cmd-recv.c
FTRACE_SRCS += utils/symbol.c utils/rbtree.c utils/debug.c
FTRACE_SRCS += utils/filter.c utils/kernel.c utils/utils.c utils/session.c
FTRACE_SRCS += utils/fstack.c utils/data-file.c utils/pager.c utils/demangle.c
FTRACE_SRCS += arch/$(ARCH)/cpuinfo.c
FTRACE_OBJS  = $(FTRACE_SRCS:.c=.o)
FTRACE_HDRS := ftrace.h libmcount/mcount.h utils/utils.h utils/filter.h
FTRACE_HDRS += utils/symbol.h utils/rbtree.h utils/list.h

LIBMCOUNT_SRCS  = $(filter-out %-nop.c,$(wildcard libmcount/*.c))
LIBMCOUNT_SRCS += utils/symbol.c utils/debug.c utils/rbtree.c utils/filter.c
LIBMCOUNT_SRCS += utils/demangle.c
LIBMCOUNT_OBJS  = $(LIBMCOUNT_SRCS:.c=.op)
LIBMCOUNT_HDRS  = libmcount/mcount.h utils/utils.h utils/symbol.h utils/filter.h
LIBMCOUNT_HDRS += utils/rbtree.h

LIBMCOUNT_NOP_SRCS = libmcount/mcount-nop.c
LIBMCOUNT_NOP_OBJS = $(LIBMCOUNT_NOP_SRCS:.c=.op)

LIBMCOUNT_FAST_SRCS = utils/symbol.c utils/debug.c utils/demangle.c
LIBMCOUNT_FAST_OBJS = $(LIBMCOUNT_FAST_SRCS:.c=.op) libmcount/mcount-fast.op

LIBMCOUNT_SINGLE_SRCS := utils/symbol.c utils/debug.c utils/rbtree.c utils/filter.c
LIBMCOUNT_SINGLE_SRCS += utils/demangle.c
LIBMCOUNT_SINGLE_OBJS = $(LIBMCOUNT_SINGLE_SRCS:.c=.op) libmcount/mcount-single.op

LIBMCOUNT_FAST_SINGLE_SRCS = utils/symbol.c utils/debug.c utils/demangle.c
LIBMCOUNT_FAST_SINGLE_OBJS = $(LIBMCOUNT_FAST_SINGLE_SRCS:.c=.op) libmcount/mcount-fast-single.op


CFLAGS_libmcount/mcount-fast.op = -DDISABLE_MCOUNT_FILTER
CFLAGS_libmcount/mcount-single.op = -DSINGLE_THREAD
CFLAGS_libmcount/mcount-fast-single.op = -DDISABLE_MCOUNT_FILTER -DSINGLE_THREAD

CFLAGS_utils/demangle.o  = -Wno-unused-value
CFLAGS_utils/demangle.op = -Wno-unused-value

MAKEFLAGS = --no-print-directory


all: $(TARGETS)

$(LIBMCOUNT_OBJS): %.op: %.c $(LIBMCOUNT_HDRS) FLAGS
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

libmcount/mcount-nop.op: libmcount/mcount-nop.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

libmcount/mcount-fast.op: libmcount/mcount.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

libmcount/mcount-single.op: libmcount/mcount.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

libmcount/mcount-fast-single.op: libmcount/mcount.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

arch/$(ARCH)/entry.op: $(wildcard arch/$(ARCH)/*.[cS]) FLAGS
	@$(MAKE) -B -C arch/$(ARCH) $(notdir $@)

libmcount/libmcount.so: $(LIBMCOUNT_OBJS) arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount/libmcount-nop.so: $(LIBMCOUNT_NOP_OBJS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount/libmcount-fast.so: $(LIBMCOUNT_FAST_OBJS) arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount/libmcount-single.so: $(LIBMCOUNT_SINGLE_OBJS) arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount/libmcount-fast-single.so: $(LIBMCOUNT_FAST_SINGLE_OBJS) arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libtraceevent/libtraceevent.a: PHONY
	@$(MAKE) -sC libtraceevent

ftrace.o: ftrace.c version.h $(FTRACE_HDRS) FLAGS
	$(QUIET_CC)$(CC) $(CFLAGS) -c -o $@ $<

$(filter-out ftrace.o,$(FTRACE_OBJS)): %.o: %.c $(FTRACE_HDRS) FLAGS
	$(QUIET_CC)$(CC) $(CFLAGS) -c -o $@ $<

FLAGS:
ifneq ($(BUILD_FLAGS),$(SAVED_FLAGS))
	$(QUIET_GEN)$(shell echo "$(BUILD_FLAGS)" > FLAGS)
endif

version.h: PHONY
	@misc/version.sh $(VERSION_GIT)

ftrace: libtraceevent/libtraceevent.a $(FTRACE_OBJS)
	$(QUIET_LINK)$(CC) $(CFLAGS) -o $@ $(FTRACE_OBJS) $(LDFLAGS)

install: all
	@$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	@$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(call QUIET_INSTALL, ftrace)
	@$(INSTALL) ftrace         $(DESTDIR)$(bindir)/ftrace
	$(call QUIET_INSTALL, libmcount.so)
	@$(INSTALL) libmcount/libmcount.so   $(DESTDIR)$(libdir)/libmcount.so
	$(call QUIET_INSTALL, libmcount-nop.so)
	@$(INSTALL) libmcount/libmcount-nop.so $(DESTDIR)$(libdir)/libmcount-nop.so
	$(call QUIET_INSTALL, libmcount-fast.so)
	@$(INSTALL) libmcount/libmcount-fast.so $(DESTDIR)$(libdir)/libmcount-fast.so
	$(call QUIET_INSTALL, libmcount-single.so)
	@$(INSTALL) libmcount/libmcount-single.so $(DESTDIR)$(libdir)/libmcount-single.so
	$(call QUIET_INSTALL, libmcount-fast-single.so)
	@$(INSTALL) libmcount/libmcount-fast-single.so $(DESTDIR)$(libdir)/libmcount-fast-single.so
	@$(MAKE) -sC doc install DESTDIR=$(DESTDIR)$(mandir)
	@if [ `id -u` = 0 ]; then ldconfig $(DESTDIR)$(libdir); fi

test: all
	@$(MAKE) -C tests ARCH=$(ARCH) TESTARG="$(TESTARG)" test

dist:
	@git archive --prefix=ftrace-$(VERSION)/ $(VERSION_GIT) -o ftrace-$(VERSION).tar
	@tar rf ftrace-$(VERSION).tar --transform="s|^|ftrace-$(VERSION)/|" version.h
	@gzip ftrace-$(VERSION).tar

doc:
	@$(MAKE) -C doc

clean:
	$(call QUIET_CLEAN, ftrace)
	@$(RM) *.o *.op *.so utils/*.o utils/*.op libmcount/*.op
	@$(RM) ftrace.data* gmon.out FLAGS $(TARGETS)
	@$(RM) ftrace-*.tar.gz
	@$(MAKE) -sC arch/$(ARCH) clean
	@$(MAKE) -sC tests ARCH=$(ARCH) clean
	@$(MAKE) -sC config check-clean BUILD_FEATURE_CHECKS=0
	@$(MAKE) -sC doc clean
	@$(MAKE) -sC libtraceevent clean

.PHONY: all clean test dist doc PHONY
