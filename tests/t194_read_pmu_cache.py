#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
            [32417] | main() {
            [32417] |   a() {
            [32417] |     b() {
            [32417] |       /* read:pmu-cache (refers=2105, misses=271) */
            [32417] |       c() {
   0.479 us [32417] |         getpid();
   3.014 us [32417] |       } /* c */
            [32417] |       /* diff:pmu-cache (refers=+23, misses=+5, hit=78%) */
  16.914 us [32417] |     } /* b */
  17.083 us [32417] |   } /* a */
  17.873 us [32417] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP
        return TestCase.TEST_SUCCESS

    def setup(self):
        self.option = '-F main -T b@read=pmu-cache'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            func = ln.split('|', 1)[-1]
            # remove actual numbers in pmu-cache
            if func.find('read:pmu-cache') > 0:
                func = '       /* read:pmu-cache */'
            if func.find('diff:pmu-cache') > 0:
                func = '       /* diff:pmu-cache */'
            result.append(func)

        return '\n'.join(result)
