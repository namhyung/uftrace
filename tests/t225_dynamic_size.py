#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'unroll', """
# DURATION    TID     FUNCTION
            [ 72208] | main() {
   0.252 us [ 72208] |   big();
   1.802 us [ 72208] | } /* main */

""")

    def prerun(self, timeout):
        if not TestBase.check_arch_full_dynamic_support(self):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = self.strip_tracing_flags(cflags)
        cflags += ' -funroll-loops'
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-P. -Z 100'
