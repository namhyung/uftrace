CC = gcc
RM = rm -f

ASFLAGS = -g -D_GNU_SOURCE
CFLAGS = -O2 -g -D_GNU_SOURCE
#CFLAGS-DEBUG = -g -D_GNU_SOURCE
LDFLAGS = -lelf

CFLAGS += -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers

uname_M := $(shell uname -m 2>/dev/null || echo not)

ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/arm.*/arm/ )
ifeq ($(ARCH),x86_64)
  ifneq ($(findstring m32,$(CFLAGS)),)
    override ARCH := i386
  endif
endif

TARGETS = libmcount.so ftrace

FTRACE_SRCS = ftrace.c symbol.c rbtree.c
FTRACE_OBJS = $(FTRACE_SRCS:.c=.o)

MAKEFLAGS = --no-print-directory

all: $(TARGETS)

mcount.op: mcount.c mcount.h
	$(CC) $(CFLAGS) -fPIC -c -fvisibility=hidden -o $@ $< -pthread

symbol.op: symbol.c symbol.h
	$(CC) $(CFLAGS) -fPIC -c -fvisibility=hidden -o $@ $<

arch/$(ARCH)/entry.op: PHONY
	@$(MAKE) -C arch/$(ARCH)

libmcount.so: mcount.op symbol.op arch/$(ARCH)/entry.op
	$(CC) -shared -o $@ $^ -pthread -lelf -lrt

ftrace: $(FTRACE_SRCS) mcount.h symbol.h utils.h rbtree.h
	$(CC) $(CFLAGS) -o $@ $(FTRACE_SRCS) $(LDFLAGS) -lstdc++

test: all
	@$(MAKE) -C tests test

clean:
	$(RM) *.o *.op $(TARGETS) ftrace.data* gmon.out
	@$(MAKE) -C tests clean
	@$(MAKE) -C arch/$(ARCH) clean

.PHONY: all clean test PHONY
