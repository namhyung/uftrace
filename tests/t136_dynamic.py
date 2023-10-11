#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
   2.405 us [28141] |   a();
   3.005 us [28141] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        if not TestBase.check_arch_mfentry_mnop_mcount_support(self):
            return TestBase.TEST_SKIP
        if cflags.find('-finstrument-functions') >= 0:
             return TestBase.TEST_SKIP
        if self.supported_lang['C']['cc'] == 'clang':
            return TestBase.TEST_SKIP
        cflags += ' -mfentry -mnop-mcount'
        cflags += ' -fno-pie -fno-plt'  # workaround of build failure
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-P "a.?" --no-libcall'
