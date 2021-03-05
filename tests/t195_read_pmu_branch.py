#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
            [32417] | main() {
            [32417] |   a() {
            [32417] |     b() {
            [32417] |       /* read:pmu-branch (branch=15482, misses=1192) */
            [32417] |       c() {
   0.479 us [32417] |         getpid();
   3.014 us [32417] |       } /* c */
            [32417] |       /* diff:pmu-branch (branch=+785, misses=+71, predict=90%) */
  16.914 us [32417] |     } /* b */
  17.083 us [32417] |   } /* a */
  17.873 us [32417] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP
        return TestCase.TEST_SUCCESS

    def setup(self):
        self.option = '-F main -T b@read=pmu-branch'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            func = ln.split('|', 1)[-1]
            # remove actual numbers in pmu-branch
            if func.find('read:pmu-branch') > 0:
                func = '       /* read:pmu-branch */'
            if func.find('diff:pmu-branch') > 0:
                func = '       /* diff:pmu-branch */'
            result.append(func)

        return '\n'.join(result)
