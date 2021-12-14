#
# func-histogram.py : print histogram of given function's execution time
#
#  Usage: func-histogram.py [-- -u <unit>] <function>
#    Unit is one of ns, us, ms, s, m
#
#  $ uftrace script -S scripts/func-histogram.py  read
#  histogram of function latency of 'read'
#
#   <     0us  :          0  (  0.0 %)
#   <     1us  :          0  (  0.0 %)
#   <     2us  :          5  (  2.3 %)
#   <     4us  :         11  (  5.1 %)
#   <     8us  :         24  ( 11.1 %)
#   <    16us  :         41  ( 19.0 %)
#   <    32us  :         68  ( 31.5 %)
#   <    64us  :         49  ( 22.7 %)
#   <   128us  :         16  (  7.4 %)
#   <   256us  :          2  (  0.9 %)
#   <   512us  :          0  (  0.0 %)
#   <  1024us  :          0  (  0.0 %)
#   >= 1024us  :          0  (  0.0 %)
#

func = ""
unit = "us"
histo = None

divider = {
    "ns": 1,
    "us": 1000,
    "ms": 1000000,
    "s": 1000000000,
    "m": 60000000000,
}


def create_histogram():
    h = []
    # 1 ~ 1024 (logarithm) = 11 + 2 (= lower/upper bounds)
    for i in range(13):
        h.append(0)
    return h


def get_histogram_index(val):
    if val < 0:
        return 0
    val = int(val / divider[unit])
    for i in range(11):
        if val < (1 << i):
            return i + 1
    return 12


def print_histogram():
    print("histogram of function latency of '%s'\n" % func)

    total = sum(histo)
    if total == 0:
        print("no value")
        return

    print(" <  %4d%-2s  : %10d  (%5.1f %%)" % (0, unit, histo[0], 100.0 * histo[0] / total))
    for i in range(11):
        print(
            " <  %4d%-2s  : %10d  (%5.1f %%)"
            % (1 << i, unit, histo[i + 1], 100.0 * histo[i + 1] / total)
        )
    print(" >= %4d%-2s  : %10d  (%5.1f %%)" % (1024, unit, histo[12], 100.0 * histo[12] / total))


def parse_args(args):
    global func, unit
    if args[0] == "-u" or args[0] == "--unit":
        unit = args[1]
        func = args[2]
    else:
        unit = "us"
        func = args[0]


#
# uftrace interface functions
#
def uftrace_begin(ctx):
    global histo
    if len(ctx["cmds"]) == 0:
        print("Usage: func-histogram.py [-- -u <unit>] <function>")
        print("  Unit is one of ns, us, ms, s or m")
        return
    parse_args(ctx["cmds"])
    if unit not in divider:
        print("Usage: invalid unit: %s" % unit)
        return
    histo = create_histogram()


def uftrace_entry(ctx):
    pass


def uftrace_exit(ctx):
    global histo
    if histo is None:
        return
    if ctx["name"] != func:
        return
    if "duration" not in ctx:
        return
    dur = int(ctx["duration"])
    idx = get_histogram_index(dur)
    histo[idx] += 1


def uftrace_end():
    if histo is None:
        return
    print_histogram()
