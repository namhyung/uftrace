#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sdt', """
# DURATION    TID     FUNCTION
   9.392 us [28141] | __monstartup();
  12.912 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   foo() {
            [28141] |     /* uftrace:event */
   2.896 us [28141] |   } /* foo */
   3.017 us [28141] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        if not TestBase.check_arch_sdt_support(self):
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-E uftrace:* --match glob'

    def runcmd(self):
        cmd = TestBase.runcmd(self)
        # change it to glob matching pattern
        return cmd.replace('-P .', '-P "*"')
