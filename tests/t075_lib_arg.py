#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
# DURATION    TID     FUNCTION
            [17458] | lib_a(4095) {
            [17458] |   lib_b(4096) {
   5.193 us [17458] |     lib_c(4095);
   6.911 us [17458] |   } /* lib_b */
   8.279 us [17458] | } /* lib_a */
""", sort='simple')

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        if TestBase.build_libabc(self, cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-libmain.c',
                                      ['libabc_test_lib.so'])

    def setup(self):
        self.option = '--force --no-libcall -A ^lib@libabc_test,arg1'
