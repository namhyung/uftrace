#!/usr/bin/env python

from runtest import TestBase
import platform

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
some functions cannot be patched dynamically
# DURATION     TID     FUNCTION
         [ 63876] | main() {
         [ 63876] |   a() {
         [ 63876] |     b() {
0.321 us [ 63876] |       c();
0.592 us [ 63876] |     } /* b */
0.833 us [ 63876] |   } /* a */
1.103 us [ 63876] | } /* main */
""")

    def pre(self):
        if platform.machine().startswith('arm'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = cflags.replace('-pg', '')
        cflags = cflags.replace('-finstrument-functions', '')
        cflags += ' -fno-pie -fno-plt'  # workaround of build failure
        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        uftrace  = TestBase.uftrace_cmd
        argument = '-P %s --no-libcall' % '.'
        program  = 't-' + self.name
        return '%s %s %s' % (uftrace, argument, program)
