#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-int', result="""
# DURATION    TID     FUNCTION
            [18279] | main() {
   0.371 ms [18279] |   int_add(-1, 2);
   0.118 ms [18279] |   int_sub(1, 2);
   0.711 ms [18279] |   int_mul(0x4, 3);
   0.923 ms [18279] |   int_div(4, -2);
   3.281 ms [18279] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support return value now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A "int_mul@arg2/x" -A "^int_@arg1,arg2" -A "int_add@arg1/i32"'

        if TestBase.is_32bit(self):
            # int_mul@arg1 is a 'long long', so we should skip arg2
            self.option  = '-A "int_mul@arg3/x" -A "^int_@arg1" '
            self.option += '-A "int_(add|sub|div)@arg2" -A "int_mul@arg1/i64" '
