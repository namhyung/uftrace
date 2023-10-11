#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
# DURATION     TID     FUNCTION
            [  3309] | main() {
            [  3324] | a() {
            [  3324] |   b() {
            [  3324] |     c() {
            [  3324] |       /* read:pmu-cycle (cycle=688, instructions=30) */
            [  3324] |       /* diff:pmu-cycle (cycle=+5739, instructions=+1338, IPC=0.23) */
  99.968 us [  3324] |     } /* c */
 120.909 us [  3324] |   } /* b */
 122.103 us [  3324] | } /* a */
 122.390 us [  3324] | } /* main */
            [  3309] |   a() {
            [  3309] |     b() {
            [  3309] |       c() {
            [  3309] |         /* read:pmu-cycle (cycle=664, instructions=30) */
            [  3309] |         /* diff:pmu-cycle (cycle=+3649, instructions=+1338, IPC=0.37) */
 109.272 us [  3309] |       } /* c */
 124.879 us [  3309] |     } /* b */
 125.839 us [  3309] |   } /* a */
   2.630 ms [  3309] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP
        return TestCase.TEST_SUCCESS

    def setup(self):
        self.option = '-T c@read=pmu-cycle --no-libcall'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            func = ln.split('|', 1)[-1]
            # remove actual numbers in pmu-cycle
            if func.find('read:pmu-cycle') > 0:
                func = '       /* read:pmu-cycle */'
            if func.find('diff:pmu-cycle') > 0:
                func = '       /* diff:pmu-cycle */'
            result.append(func)

        return '\n'.join(result)
