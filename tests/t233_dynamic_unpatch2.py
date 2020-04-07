#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dynamic', """
# DURATION     TID     FUNCTION
         [ 63876] | main() {
0.739 us [ 63876] |   foo();
1.903 us [ 63876] | } /* main */
""")

    def prerun(self, timeout):
        if TestBase.get_elf_machine(self) == 'arm':
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = cflags.replace('-pg', '')
        cflags = cflags.replace('-finstrument-functions', '')
        cflags += ' -fno-pie -fno-plt'  # workaround of build failure
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-P . -U bar --no-libcall'
