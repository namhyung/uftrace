#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'hello', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
   2.405 us [28141] |   printf("Hello %s\\n", "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234...");
   3.005 us [28141] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option  = '-A printf@arg1/s,arg2/s'
        self.exearg += ' ' + "0123456789" * 10
