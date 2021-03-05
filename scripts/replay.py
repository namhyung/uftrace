def uftrace_begin(ctx):
    print("# DURATION     TID     FUNCTION")

def uftrace_entry(ctx):
    # read arguments
    _tid = ctx["tid"]
    _depth = ctx["depth"]
    _symname = ctx["name"]

    indent = _depth * 2
    space = " " * indent

    buf = " %10s [%6d] | %s%s() {" % ("", _tid, space, _symname)
    print(buf)

def uftrace_exit(ctx):
    # read arguments
    _tid = ctx["tid"]
    _depth = ctx["depth"]
    _symname = ctx["name"]
    _duration = ctx["duration"]

    indent = _depth * 2
    space = " " * indent

    (time, unit) = get_time_and_unit(_duration)
    buf = " %7.3f %s [%6d] | %s}" % (time, unit, _tid, space)
    buf = "%s /* %s */" % (buf, _symname)
    print(buf)

def uftrace_end():
    pass

def get_time_and_unit(duration):
    duration = float(duration)
    time_unit = ""

    if duration < 100:
        divider = 1
        time_unit = "ns"
    elif duration < 1000000:
        divider = 1000
        time_unit = "us"
    elif duration < 1000000000:
        divider = 1000000
        time_unit = "ms"
    else:
        divider = 1000000000
        time_unit = " s"

    return (duration / divider, time_unit)
