#
# strings.py - print the unique strings of runtime function arguments and return values.
#
# uftrace-option: --nest-libcall --auto-args
#

strset = set()

def uftrace_entry(ctx):
    global strset
    if "args" in ctx:
        args = ctx["args"]
        for arg in args:
            if isinstance(arg, str):
                arg = arg.strip()
                if arg is not "":
                    strset.add(arg)

def uftrace_exit(ctx):
    global strset
    if "retval" in ctx:
        ret = ctx["retval"]
        if isinstance(ret, str):
            ret = ret.strip()
            if ret is not "":
                strset.add(ret)

def uftrace_end():
    global strset
    for strval in strset:
        print('"%s"' % strval)
        print("---")
