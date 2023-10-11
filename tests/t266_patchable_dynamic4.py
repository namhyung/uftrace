#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
# DURATION     TID     FUNCTION
            [  9519] | main() {
            [  9519] |   foo() {
            [  9519] |     lib_a() {
   0.625 us [  9519] |       lib_c();
   1.455 us [  9519] |     } /* lib_a */
   2.125 us [  9519] |   } /* foo */
   3.114 us [  9519] | } /* main */
""", sort='simple')

    def prerun(self, timeout):
        if not TestBase.check_arch_full_dynamic_support(self):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = self.strip_tracing_flags(cflags)

        # add patchable function entry option
        machine = TestBase.get_machine(self)
        if machine == 'x86_64':
            cflags += ' -fpatchable-function-entry=5'
        elif machine == 'aarch64':
            cflags += ' -fpatchable-function-entry=2'

        if TestBase.build_libabc(self, cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-libmain.c',
                                      ['libabc_test_lib.so'], cflags)

    def setup(self):
        self.option = '-P . -P .@libabc_test_lib.so -U lib_b@libabc_test_lib.so --no-libcall'
