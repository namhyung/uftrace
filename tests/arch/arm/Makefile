CC = gcc
RM = rm -f
FTRACE = ../../../ftrace

CFLAGS = -O0 -g -pg

TARGETS = t-thumb t-arm-thumb

all: $(TARGETS)

t-thumb: thumb.c
	$(CC) $(CFLAGS) -mthumb -o $@ $<

t-arm-thumb: a.c t.c
	$(CC) $(CFLAGS) -marm -c a.c
	$(CC) $(CFLAGS) -mthumb -c t.c
	$(CC) $(CFLAGS) -o $@ a.o t.o

test: all
	@for t in $(TARGETS); do $(FTRACE) -L ../../.. $$t; done;

clean:
	$(RM) $(TARGETS) *.o ftrace.data* gmon.out

.PHONY: clean test arch
