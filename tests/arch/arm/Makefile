CC = gcc
RM = rm -f
FTRACE = ../../../ftrace

CFLAGS = -O0 -g -pg

TARGETS = t-thumb

all: $(TARGETS)

t-thumb: thumb.c
	$(CC) $(CFLAGS) -mthumb -o $@ $<

test: all
	@for t in $(TARGETS); do $(FTRACE) -L ../../.. $$t; done;

clean:
	$(RM) $(TARGETS) *.o ftrace.data* gmon.out

.PHONY: clean test arch
