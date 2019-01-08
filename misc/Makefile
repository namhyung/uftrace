ifndef srcdir
  $(info "Start build misc programs only...")
  srcdir = $(CURDIR)/../
  objdir = $(CURDIR)/../
  $(info $(srcdir) $(objdir))
endif

include $(srcdir)/Makefile.include

#
# Note that the plain CFLAGS and LDFLAGS can be changed
# by config/Makefile later but *_*FLAGS can not.
#
DEMANGLER_CFLAGS   = $(COMMON_CFLAGS) $(CFLAGS_$@) $(CFLAGS_demangler)
SYMBOLS_CFLAGS     = $(COMMON_CFLAGS) $(CFLAGS_$@) $(CFLAGS_symbols)

DEMANGLER_LDFLAGS  = $(COMMON_LDFLAGS) $(LDFLAGS_$@) $(LDFLAGS_demangler)
SYMBOLS_LDFLAGS    = $(COMMON_LDFLAGS) $(LDFLAGS_$@) $(LDFLAGS_symbols)

ifeq ($(TRACE), 1)
  DEMANGLER_CFLAGS  += -pg -fno-omit-frame-pointer
  SYMBOLS_CFLAGS    += -pg -fno-omit-frame-pointer
endif

prebuild-misc:

_TARGETS += misc/demangler misc/symbols
TARGETS  := $(patsubst %,$(objdir)/%,$(_TARGETS))

DEMANGLER_SRCS := $(srcdir)/misc/demangler.c
DEMANGLER_OBJS := $(objdir)/misc/demangler.o
DEMANGLER_DEPS_OBJS := $(objdir)/misc/demangle.o $(objdir)/misc/debug.o

SYMBOLS_SRCS := $(srcdir)/misc/symbols.c
SYMBOLS_OBJS := $(srcdir)/misc/symbols.o
SYMBOLS_DEPS_SRCS := $(srcdir)/utils/session.c
SYMBOLS_DEPS_SRCS += $(srcdir)/utils/demangle.c $(srcdir)/utils/rbtree.c
SYMBOLS_DEPS_SRCS += $(srcdir)/utils/utils.c $(srcdir)/utils/debug.c
SYMBOLS_DEPS_SRCS += $(srcdir)/utils/filter.c $(srcdir)/utils/dwarf.c
SYMBOLS_DEPS_SRCS += $(srcdir)/utils/auto-args.c $(srcdir)/utils/regs.c
SYMBOLS_DEPS_SRCS += $(wildcard $(srcdir)/utils/symbol*.c)
SYMBOLS_DEPS_OBJS := $(patsubst $(srcdir)/utils/%.c,$(objdir)/misc/%.o,$(SYMBOLS_DEPS_SRCS))

UFTRACE_HDRS := $(filter-out $(srcdir)/version.h,$(wildcard $(srcdir)/*.h $(srcdir)/utils/*.h))
UFTRACE_HDRS += $(srcdir)/libmcount/mcount.h $(wildcard $(srcdir)/arch/$(ARCH)/*.h)
COMMON_DEPS := $(UFTRACE_HDRS)

build-misc: $(TARGETS)

$(SYMBOLS_DEPS_OBJS): $(objdir)/misc/%.o: $(srcdir)/utils/%.c $(COMMON_DEPS) $(BUILD_CHECK)
	$(QUIET_CC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(DEMANGLER_OBJS): $(DEMANGLER_SRCS) $(objdir)/version.h $(COMMON_DEPS)
	$(QUIET_CC)$(CC) $(DEMANGLER_CFLAGS) -c -o $@ $<

$(SYMBOLS_OBJS): $(srcdir)/misc/symbols.c $(objdir)/version.h $(COMMON_DEPS)
	$(QUIET_CC)$(CC) $(SYMBOLS_CFLAGS) -c -o $@ $<

$(objdir)/misc/demangler: $(DEMANGLER_OBJS) $(SYMBOLS_DEPS_OBJS)
	$(QUIET_LINK)$(CC) $(DEMANGLER_CFLAGS) -o $@ $< $(DEMANGLER_DEPS_OBJS) $(DEMANGLER_LDFLAGS)

$(objdir)/misc/symbols: $(SYMBOLS_OBJS) $(SYMBOLS_DEPS_OBJS)
	$(QUIET_LINK)$(CC) $(SYMBOLS_CFLAGS) -o $@ $< $(SYMBOLS_DEPS_OBJS) $(SYMBOLS_LDFLAGS)

$(objdir)/version.h: PHONY
	@$(srcdir)/misc/version.sh $@ $(VERSION_GIT) $(srcdir)

all:
	$(MAKE) dependency-check
	$(MAKE) prebuild-misc
	$(MAKE) build-misc

clean:
	$(Q)$(RM) $(objdir)/misc/*.o
	$(Q)$(RM) $(objdir)/misc/demangler
	$(Q)$(RM) $(objdir)/misc/symbols

.PHONY: all demangler symbols clean PHONY
