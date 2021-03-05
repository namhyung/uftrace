#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dynmain', """
# DURATION     TID     FUNCTION
         [ 26661] | main() {
         [ 26661] |   lib_a() {
         [ 26661] |     lib_b() {
1.187 us [ 26661] |       lib_c();
2.271 us [ 26661] |     } /* lib_b */
2.647 us [ 26661] |   } /* lib_a */
         [ 26661] |   lib_d() {
         [ 26661] |     lib_e() {
0.974 us [ 26661] |       lib_f();
1.266 us [ 26661] |     } /* lib_e */
1.438 us [ 26661] |   } /* lib_d */
7.607 us [ 26661] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        if TestBase.build_notrace_lib(self, 'dyn1', 'libdyn1', cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        if TestBase.build_notrace_lib(self, 'dyn2', 'libdyn2', cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL

        return TestBase.build_libmain(self, name, 's-dynmain.c',
                                      ['libdyn1.so', 'libdyn2.so'],
                                      cflags, ldflags, instrument=False)

    def setup(self):
        self.option = '-Pmain -P.@libdyn1.so -P.@libdyn2.so --no-libcall'
