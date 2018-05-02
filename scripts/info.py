def uftrace_begin(ctx):
    print(ctx["recording"])
    print(ctx["version"])
    print(ctx["args"])

def uftrace_entry(ctx):
    pass
def uftrace_exit(ctx):
    pass
