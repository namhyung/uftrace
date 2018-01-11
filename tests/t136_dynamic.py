#!/usr/bin/env python

from runtest import TestBase
import platform

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

    def pre(self):
        if platform.machine().startswith('arm'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        return TestBase.build(self, name, '-pg -mfentry -mnop-mcount', ldflags)

    def runcmd(self):
        return '%s -P %s %s' % (TestBase.uftrace_cmd, 'a.?', 't-' + self.name)
