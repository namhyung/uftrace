#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 54963] | main() {
            [ 54963] |   a() {
            [ 54963] |     b() {
   1.297 us [ 54963] |       c();
   3.772 us [ 54963] |     } /* b */
   4.376 us [ 54963] |   } /* a */
   5.484 us [ 54963] | } /* main */
""")

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

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-P . --no-libcall'
