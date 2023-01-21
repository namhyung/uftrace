#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'patchable-abc', """
# DURATION     TID     FUNCTION
            [  2331] | main() {
            [  2331] |   a() {
   0.897 us [  2331] |     c();
   2.555 us [  2331] |   } /* a */
   3.468 us [  2331] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_arch_full_dynamic_support(self):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = self.strip_tracing_flags(cflags)
        cflags += ' -Wl,--gc-sections'
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-P . --no-libcall'
