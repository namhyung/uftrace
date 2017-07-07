print("# DURATION    TID     FUNCTION")

def uftrace_entry(args):
    # read arguments
    _tid = args["tid"]
    _depth = args["depth"]
    _start_time = args["start_time"]
    _symname = args["symname"]
    _entry_addr = args["entry_addr"]

    indent = _depth * 2
    space = " " * indent

    buf = " %10s [%d] | %s%s() {" % ("", _tid, space, _symname)
    print(buf)
    return _entry_addr

def uftrace_exit(args):
    # read arguments
    _tid = args["tid"]
    _depth = args["depth"]
    _start_time = args["start_time"]
    _end_time = args["end_time"]
    _ret_addr = args["ret_addr"]
    _symname = args["symname"]

    indent = _depth * 2
    space = " " * indent

    (time, unit) = get_time_and_unit(_start_time, _end_time)
    buf = " %7.3f %s [%d] | %s}" % (time, unit, _tid, space)

    if "retval" in args:
        buf += " = %s" % str(args["retval"])
    buf += ";"
    buf = "%s /* %s */" % (buf, _symname)
    print(buf)
    return _ret_addr

def get_time_and_unit(start_time, end_time):
    duration = float(end_time - start_time)
    time_unit = ""

    if duration < 1000:
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
