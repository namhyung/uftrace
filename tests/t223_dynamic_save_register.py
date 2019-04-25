#!/usr/bin/env python

from runtest import TestBase
import platform

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dynamic-save-register', """

# DURATION     TID     FUNCTION
             [ 91012] | main() {
             [ 91012] |   foo() {
    0.159 us [ 91012] |     bar();
    0.053 us [ 91012] |     bar();
    0.050 us [ 91012] |     bar();
    0.051 us [ 91012] |     bar();
    0.051 us [ 91012] |     bar();
    0.052 us [ 91012] |     bar();
    0.058 us [ 91012] |     bar();
    1.584 us [ 91012] |   } /* foo */
    2.388 us [ 91012] | } /* main */
""")

    def pre(self):
        if platform.machine().startswith('arm'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = cflags.replace('-pg', '')
        cflags = cflags.replace('-finstrument-functions', '')
        cflags += ' -fno-plt'  # workaround of build failure
        cflags += ' -fipa-ra'
        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '-P main -P foo -P bar --no-libcall'
        program = 't-' + self.name
        return '%s %s %s' % (uftrace, options, program)
