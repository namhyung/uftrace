#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 32417] | main() {
            [ 32417] |   a() {
            [ 32417] |     b() {
            [ 32417] |       /* read:pmu-cycle (cycle=233, instructions=159) */
            [ 32417] |       c() {
            [ 32417] |         /* read:pmu-cycle (cycle=471, instructions=385) */
   0.479 us [ 32417] |         getpid();
            [ 32417] |         /* diff:pmu-cycle (cycle=+3230, instructions=+2723, IPC=0.84) */
   3.014 us [ 32417] |       } /* c */
            [ 32417] |       /* diff:pmu-cycle (cycle=+5014, instructions=+3514, IPC=0.70) */
  16.914 us [ 32417] |     } /* b */
  17.083 us [ 32417] |   } /* a */
  17.873 us [ 32417] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP
        return TestCase.TEST_SUCCESS

    def setup(self):
        self.option = "-F main -T '[bc]@read=pmu-cycle'"

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
