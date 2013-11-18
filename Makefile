CC = gcc
RM = rm -f

ASFLAGS = -g -D_GNU_SOURCE
CFLAGS = -O2 -g -D_GNU_SOURCE
CFLAGS-DEBUG = -g -D_GNU_SOURCE
LDFLAGS = -lelf -ldl

CFLAGS += -W -Wall -Wno-unused-parameter -Wno-unused-function

TARGETS = libmcount.so librtld-audit.so ftrace

FTRACE_SRCS = ftrace.c symbol.c
FTRACE_OBJS = $(FTRACE_SRCS:.c=.o)

all: $(TARGETS)

entry.o: entry.S
	$(CC) $(ASFLAGS) -fPIC -c -o $@ $<

mcount.o: mcount.c mcount.h
	$(CC) $(CFLAGS) -fPIC -c -fvisibility=hidden -o $@ $< -pthread

audit.o: audit.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

libmcount.so: mcount.o entry.o
	$(CC) -shared -o $@ $^ -pthread

librtld-audit.so: audit.o
	$(CC) -shared -o $@ $^

ftrace: $(FTRACE_SRCS) mcount.h symbol.h
	$(CC) $(CFLAGS) -o $@ $(FTRACE_SRCS) $(LDFLAGS)

test: all
	@$(MAKE) --no-print-directory -C tests test

clean:
	$(RM) *.o $(TARGETS)

.PHONY: all clean test
