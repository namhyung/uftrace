#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'data', result="""
# DURATION     TID     FUNCTION
            [ 16187] | main() {
   0.967 us [ 16187] |   foo(&static_var, 1);
   0.331 us [ 16187] |   foo(&global_var, 2);
   0.143 us [ 16187] |   foo(&weak_var, 3);
   0.166 us [ 16187] |   filecmp(&_IO_2_1_stdout_, &_IO_2_1_stderr_);
   3.189 us [ 16187] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A foo@arg1/p,arg2 -A filecmp@arg1/p,arg2/p'
