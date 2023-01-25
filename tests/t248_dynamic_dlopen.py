#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dlopen', """
# DURATION     TID     FUNCTION
            [ 29979] | main() {
 401.827 us [ 29979] |   dlopen();
   1.339 us [ 29979] |   dlsym();
            [ 29979] |   lib_a() {
            [ 29979] |     lib_b() {
   1.509 us [ 29979] |       lib_c();
   1.993 us [ 29979] |     } /* lib_b */
   2.468 us [ 29979] |   } /* lib_a */
  14.949 us [ 29979] |   dlclose();
 346.494 us [ 29979] |   dlopen();
   0.925 us [ 29979] |   dlsym();
            [ 29979] |   foo() {
   0.163 us [ 29979] |     AAA::bar();
   1.706 us [ 29979] |   } /* foo */
  11.246 us [ 29979] |   dlclose();
 788.643 us [ 29979] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_arch_full_dynamic_support(self):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = self.strip_tracing_flags(cflags)

        if TestBase.build_libabc(self, cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        if TestBase.build_libfoo(self, 'foo', cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-dlopen.c', ['libdl.so'],
                                      cflags, ldflags)

    def setup(self):
        self.option = ' -P. -P.@libfoo.so -P.@libabc_test_lib.so'
