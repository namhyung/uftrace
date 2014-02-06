CC = gcc
RM = rm -f
FTRACE = ../../../ftrace

CFLAGS = -O0 -g -pg

TARGETS = t-fentry

all: $(TARGETS)

t-fentry: fentry.c
	$(CC) $(CFLAGS) -mfentry -o $@ $<

test: all
	@for t in $(TARGETS); do $(FTRACE) -L ../../.. $$t; done;

clean:
	$(RM) $(TARGETS) *.o ftrace.data* gmon.out

.PHONY: clean test arch
