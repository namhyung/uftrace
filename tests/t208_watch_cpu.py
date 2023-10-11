#!/usr/bin/env python3

import re

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'chcpu', serial=True, result="""
# DURATION     TID     FUNCTION
            [320248] | main() {
            [320248] |   /* watch:cpu (cpu=1) */
  23.252 us [320248] |   sysconf();
   0.667 us [320248] |   sched_getcpu();
            [320248] |   sched_setaffinity() {
            [320248] |     /* watch:cpu (cpu=0) */
  75.337 us [320248] |   } /* sched_setaffinity */
            [320248] |   sched_setaffinity() {
            [320248] |     /* watch:cpu (cpu=1) */
  40.668 us [320248] |   } /* sched_setaffinity */
 146.590 us [320248] | } /* main */
""")

    def setup(self):
        # ignore unexpected memset on ARM (raspbian)
        self.option = '-F main -W cpu -N memset --no-sched'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            line = ln.split('|', 1)[-1]
            func = re.sub(r'cpu=[0-9a-f]+', 'cpu=N', line)
            result.append(func)

        return '\n'.join(result)
