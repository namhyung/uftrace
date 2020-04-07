#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
# DURATION    TID     FUNCTION
            [17455] | lib_a() {
            [17455] |   lib_b() {
  61.911 us [17455] |     lib_c();
 217.279 us [17455] |   } /* lib_b */
 566.261 us [17455] | } /* lib_a */
""", sort='simple')

    def build(self, name, cflags='', ldflags=''):
        if TestBase.build_libabc(self, cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-libmain.c',
                                      ['libabc_test_lib.so'])

    def setup(self):
        self.option = '--force --no-libcall'
