# Copyright (c) 2025 SK hynix, Inc.
# SPDX-License-Identifier: GPL-2.0
#
# func-percentile.py: print P90, P95, P99 percentiles and min, avg, max of a
# given function's total execution time
#
#  Usage: func-percentile.py [-- -u <unit>] <function>
#    Unit is one of ns, us, ms, s, m
#
#  $ uftrace script -S scripts/func-percentile.py foobar
#  P90:   1052.519 us
#  P95:   1052.710 us
#  P99:   1053.223 us
#  MIN:      5.600 us
#  AVG:    329.921 us
#  MAX:   1058.343 us


func = ''
unit = 'us'
durations = []

divider = {
    'ns': 1,
    'us': 1000,
    'ms': 1000000,
    's':  1000000000,
    'm':  60000000000,
}

def percentile(data, p):
    n = len(data)
    index = (n - 1) * (p / 100)
    lower = int(index)
    upper = min(lower + 1, n - 1)

    if lower == upper:
        return data[lower]

    # linear interpolation
    return data[lower] + ((data[upper] - data[lower]) * (index - lower))

def print_percentile():
    if len(durations) == 0:
        print("No trace")
        return

    sorted_durations = sorted(durations)

    p90 = percentile(sorted_durations, 90) / divider[unit]
    p95 = percentile(sorted_durations, 95) / divider[unit]
    p99 = percentile(sorted_durations, 99) / divider[unit]
    minimum = sorted_durations[0] / divider[unit]
    maximum = sorted_durations[-1] / divider[unit]
    avg = sum(durations) / len(durations) / divider[unit]

    print(f"P90: {p90:10.3f} {unit}")
    print(f"P95: {p95:10.3f} {unit}")
    print(f"P99: {p99:10.3f} {unit}")
    print(f"MIN: {minimum:10.3f} {unit}")
    print(f"AVG: {avg:10.3f} {unit}")
    print(f"MAX: {maximum:10.3f} {unit}")

def parse_args(args):
    global func, unit

    if args[0] == '-u' or args[0] == '--unit':
        unit = args[1]
        func = args[2]
    else:
        func = args[0]

#
# uftrace interface functions
#
def uftrace_begin(ctx):
    args = ctx["cmds"]
    if len(args) == 0:
        print("Usage: func-percentile.py [-- -u <unit>] <function>")
        print("  Unit is one of ns, us, ms, s or m")
        return
    parse_args(ctx["cmds"])
    if unit not in divider:
        print(f"Usage: invalid unit: {unit}")
        return

def uftrace_entry(ctx):
    pass

def uftrace_exit(ctx):
    if ctx["name"] != func:
        return
    if "duration" not in ctx:
        return

    duration = int(ctx["duration"])
    durations.append(duration)

def uftrace_end():
    print_percentile()
