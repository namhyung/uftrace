def uftrace_begin(ctx):
    print(ctx["record"])
    print(ctx["version"])
    print(ctx["cmds"])

def uftrace_entry(ctx):
    pass

def uftrace_exit(ctx):
    pass
