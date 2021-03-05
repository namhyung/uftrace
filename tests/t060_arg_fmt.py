#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-int', result="""
# DURATION    TID     FUNCTION
            [18278] | main() {
   0.371 ms [18278] |   int_add(-1, 2);
   0.118 ms [18278] |   int_sub();
   0.711 ms [18278] |   int_mul();
   0.923 ms [18278] |   int_div(4, 0xfe);
   3.281 ms [18278] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A "int_add@arg1/i32,arg2/u" -A "int_div@arg1/i16,arg2/x8"'
