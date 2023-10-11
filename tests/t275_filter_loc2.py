#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
# DURATION     TID     FUNCTION
            [  5295] | lib_a() {
            [  5295] |   lib_b() {
   1.457 us [  5295] |     lib_c();
   2.401 us [  5295] |   } /* lib_b */
   2.736 us [  5295] | } /* lib_a */
""", sort='simple', cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        if TestBase.build_libabc(self, cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-libmain.c',
                                      ['libabc_test_lib.so'],
                                      cflags, ldflags)

    def prepare(self):
        self.subcmd = 'record'
        self.option = '--srcline --no-libcall'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-L s-libmain.c@hide'
