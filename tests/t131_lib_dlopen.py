#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dlopen', """1
# DURATION    TID     FUNCTION
   1.404 us [22207] | __cxa_atexit();
            [22207] | main() {
  70.963 us [22207] |   dlopen();
   1.546 us [22207] |   dlsym();
            [22207] |   lib_a() {
            [22207] |     lib_b() {
   0.678 us [22207] |       lib_c();
   1.301 us [22207] |     } /* lib_b */
   2.104 us [22207] |   } /* lib_a */
  14.446 us [22207] |   dlclose();
            [22207] |   dlopen();
   0.844 us [22207] |   dlsym();
            [22207] |   foo() {
  19.601 us [22207] |     AAA::bar();
  19.869 us [22207] |   } /* foo */
  13.391 us [22207] |   dlclose();
 274.723 us [22207] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        if TestBase.build_libabc(self, cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        if TestBase.build_libfoo(self, 'foo', cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-dlopen.c', ['libdl.so'],
                                      cflags, ldflags)
