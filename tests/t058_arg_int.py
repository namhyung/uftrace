#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-int', result="""
# DURATION    TID     FUNCTION
            [18270] | main() {
   0.371 ms [18270] |   int_add(-1, 2);
   0.118 ms [18270] |   int_sub(1, 2);
   0.711 ms [18270] |   int_mul(3, 4);
   0.923 ms [18270] |   int_div(4, -2);
   3.281 ms [18270] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A "^int_@arg1,arg2"'

        if TestBase.is_32bit(self):
            # int_mul@arg1 is a 'long long', so we should skip arg2
            self.option = '-A "int_(add|sub|div)@arg1,arg2" -A "int_mul@arg1/i64,arg3"'
