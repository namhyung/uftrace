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

ifdef MAKECMDGOALS
ifneq ($(filter dist,$(MAKECMDGOALS)),)
VERSION_GIT := $(patsubst v%,%,$(shell git describe --tags))
endif
endif

# Check if bulid flags changed
BUILD_FLAGS := $(COMMON_CFLAGS) $(COMMON_LDFLAGS) $(prefix)
SAVED_FLAGS := $(shell cat FLAGS 2> /dev/null)
ifneq ($(BUILD_FLAGS),$(SAVED_FLAGS))
  $(shell echo "$(BUILD_FLAGS)" > FLAGS)
endif

all:

uname_M := $(shell uname -m 2>/dev/null || echo not)

ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/arm.*/arm/ )
ifeq ($(ARCH),x86_64)
  ifneq ($(findstring m32,$(CFLAGS)),)
    override ARCH := i386
  endif
endif

CFLAGS_mcount.op = -pthread
CFLAGS_ftrace = -DINSTALL_LIB_PATH='"$(libdir)"'

include config/Makefile


TARGETS = libmcount.so libmcount-nop.so ftrace

FTRACE_SRCS  = ftrace.c symbol.c rbtree.c info.c debug.c filter.c
FTRACE_SRCS += arch/$(ARCH)/cpuinfo.c
FTRACE_OBJS  = $(FTRACE_SRCS:.c=.o)

LIBMCOUNT_SRCS = mcount.c symbol.c debug.c rbtree.c filter.c
LIBMCOUNT_OBJS = $(LIBMCOUNT_SRCS:.c=.op)

LIBMCOUNT_NOP_SRCS = mcount-nop.c
LIBMCOUNT_NOP_OBJS = $(LIBMCOUNT_NOP_SRCS:.c=.op)

MAKEFLAGS = --no-print-directory


all: $(TARGETS)

$(LIBMCOUNT_OBJS): %.op: %.c mcount.h symbol.h utils.h rbtree.h FLAGS
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

mcount-nop.op: mcount-nop.c
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

arch/$(ARCH)/%.op: arch/$(ARCH)/*.S FLAGS
	@$(MAKE) -B -C arch/$(ARCH) $(notdir $@)

libmcount.so: $(LIBMCOUNT_OBJS) arch/$(ARCH)/entry.op
	$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount-nop.so: $(LIBMCOUNT_NOP_OBJS)
	$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

ftrace: $(FTRACE_SRCS) mcount.h symbol.h utils.h rbtree.h
	$(CC) $(CFLAGS) -o $@ $(FTRACE_SRCS) $(LDFLAGS)

install: all
	@$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	@$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	@$(INSTALL) ftrace         $(DESTDIR)$(bindir)/ftrace
	@$(INSTALL) libmcount.so   $(DESTDIR)$(libdir)/libmcount.so
	@$(MAKE) -sC doc install DESTDIR=$(DESTDIR)$(mandir)
	@ldconfig $(DESTDIR)$(libdir)

test: all
	@$(MAKE) -C tests ARCH=$(ARCH) TESTARG="$(TESTARG)" test

dist:
	git archive --format=tar.gz --prefix=ftrace-$(VERSION_GIT)/ \
		v$(VERSION_GIT) > ftrace-$(VERSION_GIT).tar.gz

doc:
	@$(MAKE) -C doc

clean:
	@$(RM) *.o *.op $(TARGETS) ftrace.data* gmon.out FLAGS
	@$(RM) ftrace-*.tar.gz
	@$(MAKE) -sC arch/$(ARCH) clean
	@$(MAKE) -sC tests ARCH=$(ARCH) clean
	@$(MAKE) -sC config check-clean BUILD_FEATURE_CHECKS=0
	@$(MAKE) -sC doc clean

.PHONY: all clean test dist doc PHONY
