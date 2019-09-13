#!/usr/bin/env python

from runtest import TestBase
import platform

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dynamic', """
# DURATION     TID     FUNCTION
         [ 63876] | main() {
0.739 us [ 63876] |   test_jmp_prolog();
0.739 us [ 63876] |   foo();
0.833 us [ 63876] |   bar();
1.903 us [ 63876] | } /* main */
""")

    def pre(self):
        if not TestBase.check_dependency(self, 'have_libcapstone') or platform.machine().startswith('arm'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = cflags.replace('-pg', '')
        cflags = cflags.replace('-finstrument-functions', '')
        cflags += ' -fno-pie -fno-plt'  # workaround of build failure
        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '-P main -P foo -P bar -P test_jmp_prolog --no-libcall'
        program = 't-' + self.name
        return '%s %s %s' % (uftrace, options, program)
