#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-int', """
# DURATION     TID      FUNCTION
   0.502 us [ 226240] | int_add(-1, 2) = 1;
""", cflags='-g', sort='simple')

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-a -F "int_add@if:arg1/i32 < 0"'
