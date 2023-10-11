#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dynamic', """
# DURATION     TID     FUNCTION
         [ 63876] | main() {
0.739 us [ 63876] |   foo();
0.833 us [ 63876] |   bar();
1.903 us [ 63876] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_arch_full_dynamic_support(self):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = self.strip_tracing_flags(cflags)
        cflags += ' -fno-pie -fno-plt'  # workaround of build failure
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-P main -P foo -P bar --no-libcall'
