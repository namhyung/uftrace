#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dlopen', """
# DURATION     TID     FUNCTION
           [108977] | main() {
187.389 us [108977] |   dlopen();
  0.754 us [108977] |   dlsym();
           [108977] |   lib_a() {
           [108977] |     lib_b() {
  1.083 us [108977] |       lib_c();
  1.331 us [108977] |     } /* lib_b */
  1.614 us [108977] |   } /* lib_a */
  9.988 us [108977] |   dlclose();
174.777 us [108977] |   dlopen();
  0.764 us [108977] |   dlsym();
  0.765 us [108977] |   foo();
108.059 us [108977] |   dlclose();
488.088 us [108977] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        cflags = cflags.replace('-pg', '')
        cflags = cflags.replace('-finstrument-functions', '')

        if TestBase.build_libabc(self, cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        if TestBase.build_libfoo(self, 'foo', cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-dlopen.c', ['libdl.so'],
                                      cflags, ldflags)

    def setup(self):
        self.option = ' -P. -P.@libfoo.so -P.@libabc_test_lib.so'
