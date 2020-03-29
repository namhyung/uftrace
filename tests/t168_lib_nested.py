#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'nest-libcall', """1
# DURATION    TID     FUNCTION
            [ 5363] | main() {
            [ 5363] |   lib_a() {
   0.538 us [ 5363] |     getpid();
   2.793 us [ 5363] |   } /* lib_a */
            [ 5363] |   foo() {
   9.405 us [ 5363] |     AAA::bar();
  17.133 us [ 5363] |   } /* foo */
  21.093 us [ 5363] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        if TestBase.build_libabc(self, '', '') != 0:
            return TestBase.TEST_BUILD_FAIL
        if TestBase.build_libfoo(self, 'foo', '', '') != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-nest-libcall.c',
                                      ['libabc_test_lib.so', 'libfoo.so'],
                                      cflags, ldflags)

    def setup(self):
        self.option = '-D3 --nest-libcall'
