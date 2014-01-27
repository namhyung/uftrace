CC = gcc
RM = rm -f
FTRACE = ../ftrace

CFLAGS = -O0 -g -pg

TARGETS = t-abc t-threaded-abc t-arg t-fentry

all: $(TARGETS)

t-abc: abc.c
	$(CC) $(CFLAGS) -o $@ $<

t-threaded-abc: threaded-abc.c
	$(CC) $(CFLAGS) -o $@ $< -pthread

t-arg: arg.c
	$(CC) $(CFLAGS) -o $@ $<

t-fentry: fentry.c
	$(CC) $(CFLAGS) -mfentry -o $@ $<

test: all
	@for t in $(TARGETS); do $(FTRACE) -L .. $$t 1 2 3; done;

clean:
	$(RM) $(TARGETS) *.o

.PHONY: clean test
