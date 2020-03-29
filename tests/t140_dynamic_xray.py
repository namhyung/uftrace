#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   a() {
   0.753 us [28141] |     getpid();
   2.405 us [28141] |   } /* a */
   3.005 us [28141] | } /* main */
""")

    def prerun(self, timeout):
        if TestBase.get_elf_machine(self) == 'arm':
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        old_cc = TestBase.supported_lang['C']['cc']
        TestBase.supported_lang['C']['cc'] = 'clang'
        r = TestBase.build(self, name, '-fxray-instrument -fxray-instruction-threshold=1', '-lstdc++')
        TestBase.supported_lang['C']['cc'] = old_cc
        return r

    def setup(self):
        self.option = "-P 'a.?'"
