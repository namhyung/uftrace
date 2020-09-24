#
# retval-histogram.py : print histogram of given function's return values
#
#  Usage: retval-histogram.py [-- -u <unit>] <function>
#    Unit is one of b, k, m, g
#
#  $ uftrace script -S scripts/retval-histogram.py  strlen
#  histogram of return value of 'strlen'
#
#   <     0b  :          0  (  0.0 %)
#   <     2b  :          5  (  2.3 %)
#   <     4b  :         11  (  5.1 %)
#   <     8b  :         24  ( 11.1 %)
#   <    16b  :         41  ( 19.0 %)
#   <    32b  :         68  ( 31.5 %)
#   <    64b  :         49  ( 22.7 %)
#   <   128b  :         16  (  7.4 %)
#   <   256b  :          2  (  0.9 %)
#   <   512b  :          0  (  0.0 %)
#   <  1024b  :          0  (  0.0 %)
#   >= 1024b  :          0  (  0.0 %)
#

func = ''
unit = 'b'
histo = None

divider = {
    'b': 1,
    'k': 1000,
    'K': 1000,
    'm': 1000000,
    'M': 1000000,
    'g': 1000000000,
    'G': 1000000000,
}

def create_histogram():
    h = []
    # 1 ~ 1024 (logarithm) = 10 + 2 (= lower/upper bounds)
    for i in range(12):
        h.append(0)
    return h

def get_histogram_index(val):
    if val < 0:
        return 0
    val = int(val / divider[unit])
    for i in range(10):
        if val < (1 << (i+1)):
            return i+1
    return 11

def print_histogram():
    print("histogram of return value of '%s'\n" % func)

    total = sum(histo)
    if total == 0:
        print("no value")
        return

    print(" <  %4d%s  : %10d  (%5.1f %%)" % (0, unit, histo[0], 100.0 * histo[0] / total))
    for i in range(10):
        print(" <  %4d%s  : %10d  (%5.1f %%)" % (1 << (i+1), unit, histo[i+1], 100.0 * histo[i+1] / total))
    print(" >= %4d%s  : %10d  (%5.1f %%)" % (1024, unit, histo[11], 100.0 * histo[11] / total))

def parse_args(args):
    global func, unit
    if args[0] == '-u' or args[0] == '--unit':
        unit = args[1]
        func = args[2]
    else:
        unit = 'b'
        func = args[0]

#
# uftrace interface functions
#
def uftrace_begin(ctx):
    global histo
    if len(ctx["cmds"]) == 0:
        print("Usage: retval-histogram.py [-- -u <unit>] <function>")
        print("  Unit is one of b, k, m, g")
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
    if "retval" not in ctx:
        return
    retval = int(ctx["retval"])
    idx = get_histogram_index(retval)
    histo[idx] += 1

def uftrace_end():
    if histo is None:
        return
    print_histogram()
