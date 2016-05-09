all:

has_pandoc := $(shell pandoc -v > /dev/null 2>&1 && echo yes || echo no)

RM := rm -f
INSTALL = install

include ../config/Makefile.include

COMMANDS = record replay live report recv info
MANPAGES = uftrace.1 $(patsubst %,uftrace-%.1,$(COMMANDS))

ifeq ($(has_pandoc),yes)

all: $(MANPAGES)

%.1: %.md
	$(QUIET_GEN)pandoc -s $< -t man -o $@

# $(DESTDIR) already contains $(mandir) by ../Makefile
install: all
	$(call QUIET_INSTALL, man-pages)
	$(INSTALL) -d -m 755 $(DESTDIR)/man1
	for F in $(MANPAGES); do $(INSTALL) -m 644 $${F} $(DESTDIR)/man1; done

clean:
	$(call QUIET_CLEAN, man-pages)
	$(RM) *.1

else
  ifneq ($(MAKECMDGOALS),clean)
    $(warning To install man pages, please install 'pandoc'.)
  endif

install:

clean:

endif

.PHONY: all clean PHONY
