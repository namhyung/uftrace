all:

has_pandoc := $(shell pandoc -v &> /dev/null && echo yes || echo no)

INSTALL = install

COMMANDS = record replay live report info
MANPAGES = ftrace.1 $(patsubst %,ftrace-%.1,$(COMMANDS))

ifeq ($(has_pandoc),yes)

all: $(MANPAGES)

%.1: %.md
	pandoc -s $< -t man -o $@

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)/man1
	for F in $(MANPAGES); do $(INSTALL) -m 644 $${F} $(DESTDIR)/man1; done

else
  ifneq ($(MAKECMDGOALS),clean)
    $(warning To install man pages, please install 'pandoc'.)
  endif
endif

clean:
	rm -f *.1

.PHONY: all clean PHONY
