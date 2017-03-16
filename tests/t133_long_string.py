#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'hello', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
   2.405 us [28141] |   printf("Hello %s\\n", "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");
   3.005 us [28141] | } /* main */
""")

    def runcmd(self):
        return '%s -A printf@arg1/s,arg2/s %s %s' % \
            (TestBase.ftrace, 't-' + self.name, "0123456789" * 10)
