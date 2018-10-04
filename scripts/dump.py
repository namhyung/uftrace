#
# dump.py
#
# Target program is executed with the given uftrace options below.
# uftrace-option: --auto-args --nest-libcall
#

# uftrace_entry and uftrace_exit are executed only for listed functions.
# UFTRACE_FUNCS = [ "foo", "bar" ]

# uftrace_begin is optional, so can be omitted.
def uftrace_begin(ctx):
    print("uftrace_begin(ctx)")
    print("  record  : %s" % ctx["record"])
    print("  version : %s" % ctx["version"])
    if "cmds" in ctx:
        print("  cmds    : %s" % " ".join(ctx["cmds"]))
    print("")

# uftrace_entry is executed at the entry of each function.
# if UFTRACE_FUNCS is defined, only the listed functions enter here.
def uftrace_entry(ctx):
    _tid        = ctx["tid"]
    _depth      = ctx["depth"]
    _time       = ctx["timestamp"]
    # _duration = ctx["duration"]        # exit only
    _address    = ctx["address"]
    _name       = ctx["name"]

    unit = 10 ** 9
    print("%d.%d %6d: [entry] %s(%x) depth: %d" %
            (_time / unit, _time % unit, _tid, _name, _address, _depth))

    if "args" in ctx:
        for i in range(len(ctx["args"])):
            arg = ctx["args"][i]
            print("  args[%d] %s: %s" % (i, type(arg), arg))

# uftrace_exit is executed at the exit of each function.
# if UFTRACE_FUNCS is defined, only the listed functions enter here.
def uftrace_exit(ctx):
    _tid        = ctx["tid"]
    _depth      = ctx["depth"]
    _time       = ctx["timestamp"]
    _duration   = ctx["duration"]        # not used here
    _address    = ctx["address"]
    _name       = ctx["name"]

    unit = 10 ** 9
    print("%d.%d %6d: [exit ] %s(%x) depth: %d" %
            (_time / unit, _time % unit, _tid, _name, _address, _depth))

    if "retval" in ctx:
        ret = ctx["retval"]
        print("  retval  %s: %s" % (type(ret), ret))

# uftrace_end is optional, so can be omitted.
def uftrace_end():
    print("\nuftrace_end()")
