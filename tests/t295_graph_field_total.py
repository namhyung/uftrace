#!/usr/bin/env python3

import re

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
# Function Call Graph for 'main' (session: a0e1748898d10ad1)
========== FUNCTION CALL GRAPH ==========
# TOTAL AVG   TOTAL MAX  TOTAL MIN   FUNCTION
   11.725 ms   11.725 ms   11.725 ms : (1) t-sort
   11.563 ms   11.563 ms   11.563 ms :  +-(1) main
   28.875 us   47.958 us    9.792 us :     +-(2) foo
    8.736 us   36.625 us    3.125 us :     | (6) loop
                                     :     |
   11.436 ms   11.436 ms   11.436 ms :     +-(1) bar
   11.413 ms   11.413 ms   11.413 ms :       (1) usleep
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.option = '-F main -f total-avg,total-max,total-min'
        self.exearg = ''

    def sort(self, output):
        result = []
        invalid_found = False

        for ln in output.split('\n'):
            if not ln.strip() or ln.startswith('#') or ':' not in ln:
                continue

            match = re.search(r'\((\d+)\)', ln)
            if not match:
                continue

            call_count = int(match.group(1))

            parts = ln.split(':')[0].strip().split()
            if len(parts) < 6:
                continue

            unit = parts[1].lower()

            try:
                def convert(value):
                    v = float(value)
                    if unit == 'us':
                        return v
                    elif unit == 'ms':
                        return v * 1000
                    elif unit == 'ns':
                        return v / 1000
                    else:
                        raise ValueError(f"Unknown time unit: {unit}")

                avg = convert(parts[0])
                max_ = convert(parts[2])
                min_ = convert(parts[4])

                func_match = re.search(r'\(\d+\)\s+(\S+)', ln)
                func_name = func_match.group(1) if func_match else 'UNKNOWN'

                # Functions that are executed only once – compare if times are the same
                if call_count == 1:
                    if not (avg == min_ == max_):
                        invalid_found = True
                        result.append(f"{func_name} : NG")
                    else:
                        result.append(f"{func_name} : OK")
                    continue

                #Compare each field to ensure it has the correct size.
                ok_ng = "OK" if min_ <= avg <= max_ else "NG"
                if ok_ng == "NG":
                    invalid_found = True

                result.append(f"{func_name} : {ok_ng}")

            except Exception:
                invalid_found = True
                result.append(f"{ln:<40} : Parse error")

        return '\n'.join(result)
