# Copyright (c) 2025 SK hynix, Inc.
# SPDX-License-Identifier: GPL-2.0
#
# func-percentile.py: print P90, P95, P99 percentiles and min, avg, max of a
# given function's total execution time
#
#  Usage: func-percentile.py [-- -u <unit>] <function>
#    Unit is one of ns, us, ms, s, m, h or auto (default)
#
#  $ uftrace script -S scripts/func-percentile.py foobar
#  P90:     1.052 ms
#  P95:     1.052 ms
#  P99:     1.053 ms
#  MIN:     5.600 us
#  AVG:   329.921 us
#  MAX:     1.058 ms

func = ''
unit = 'auto'
unit_opts = [ 'us', 'ms', 's', 'm', 'h', 'auto' ]
durations = []

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[32m"
YELLOW = "\033[33m"

unit_us = f"{RESET}us{RESET}"
unit_ms = f"{GREEN}ms{RESET}"
unit_s = f"{YELLOW} s{RESET}"
unit_m = f"{RED} m{RESET}"
unit_h = f"{RED} h{RESET}"
units = [ unit_us, unit_ms, unit_s, unit_m, unit_h ]

INT_MAX = 2**31 - 1
limit = [ 1000, 1000, 1000, 60, 24, INT_MAX ]

def time_with_unit(time_ns, selected_unit):
    delta = time_ns
    unit_idx = 0

    for idx in range(len(limit) - 1):
        divider = limit[idx]
        unit_idx = idx
        delta_small = int(delta % divider)
        delta = int(delta / limit[idx])
        if selected_unit is not None:
            if idx == selected_unit:
                break
        elif delta < limit[idx + 1]:
            break

    return f"{delta:>5}.{delta_small:03d} {units[unit_idx]}"

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

    selected_unit = None
    if unit != 'auto' and unit in unit_opts:
        selected_unit = unit_opts.index(unit)

    p90 = time_with_unit(percentile(sorted_durations, 90), selected_unit)
    p95 = time_with_unit(percentile(sorted_durations, 95), selected_unit)
    p99 = time_with_unit(percentile(sorted_durations, 99), selected_unit)
    minimum = time_with_unit(sorted_durations[0], selected_unit)
    maximum = time_with_unit(sorted_durations[-1], selected_unit)
    avg = time_with_unit(sum(durations) / len(durations), selected_unit)

    print(f"P90: {p90}")
    print(f"P95: {p95}")
    print(f"P99: {p99}")
    print(f"MIN: {minimum}")
    print(f"AVG: {avg}")
    print(f"MAX: {maximum}")

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
        print("  Unit is one of ns, us, ms, s, m, h or auto (dufault)")
        return
    parse_args(ctx["cmds"])
    if unit not in unit_opts:
        print(f"WARN: invalid unit: {unit}. fallback to default unit: auto.")
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
