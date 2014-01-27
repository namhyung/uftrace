CC = gcc
RM = rm -f

ASFLAGS = -g -D_GNU_SOURCE
CFLAGS = -O2 -g -D_GNU_SOURCE
#CFLAGS-DEBUG = -g -D_GNU_SOURCE
LDFLAGS = -lelf

CFLAGS += -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers

TARGETS = libmcount.so ftrace

FTRACE_SRCS = ftrace.c symbol.c rbtree.c
FTRACE_OBJS = $(FTRACE_SRCS:.c=.o)

all: $(TARGETS)

entry.op: entry.S
	$(CC) $(ASFLAGS) -fPIC -c -o $@ $<

plthook.op: plthook.S
	$(CC) $(ASFLAGS) -fPIC -c -o $@ $<

fentry.op: fentry.S
	$(CC) $(ASFLAGS) -fPIC -c -o $@ $<

mcount.op: mcount.c mcount.h
	$(CC) $(CFLAGS) -fPIC -c -fvisibility=hidden -o $@ $< -pthread

symbol.op: symbol.c symbol.h
	$(CC) $(CFLAGS) -fPIC -c -fvisibility=hidden -o $@ $<

libmcount.so: mcount.op entry.op plthook.op symbol.op fentry.op
	$(CC) -shared -o $@ $^ -pthread -lelf

ftrace: $(FTRACE_SRCS) mcount.h symbol.h utils.h rbtree.h
	$(CC) $(CFLAGS) -o $@ $(FTRACE_SRCS) $(LDFLAGS)

test: all
	@$(MAKE) --no-print-directory -C tests test

clean:
	$(RM) *.o *.op $(TARGETS)

.PHONY: all clean test
