#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-char', result="""
# DURATION    TID     FUNCTION
            [18279] | main() {
   0.371 ms [18279] |   foo('f', 'o', 'o');
   0.923 ms [18279] |   bar('\\0', 'B', 97, 0x72);
   3.281 ms [18279] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option  = '-A "foo@arg1/c,arg2/c,arg3/c" '
        self.option += '-A "bar@arg1/c,arg2/c,arg3/i,arg4/x8"'
