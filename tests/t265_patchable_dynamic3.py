#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'patchable-abc', """
# DURATION     TID     FUNCTION
            [  6907] | main() {
   1.138 us [  6907] |   c();
   4.345 us [  6907] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_arch_full_dynamic_support(self):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = self.strip_tracing_flags(cflags)
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-P . -U a --no-libcall'
