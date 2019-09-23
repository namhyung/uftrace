#!/usr/bin/env python

from runtest import TestBase
import platform

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   b() {
   0.913 us [28141] |     c();
   2.210 us [28141] |   } /* b */
   3.005 us [28141] | } /* main */
""")

    def pre(self):
        if platform.machine().startswith('arm'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags += ' -mfentry -mnop-mcount'
        cflags += ' -fno-pie -fno-plt'  # workaround of build failure
        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        uftrace  = TestBase.uftrace_cmd
        argument = '-P . -U a --no-libcall'
        program  = 't-' + self.name
        return '%s %s %s' % (uftrace, argument, program)
