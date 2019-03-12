#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', """
# DURATION    TID     FUNCTION
            [ 9875] | main() {
            [ 9875] |   fopen() {
  14.416 us [ 9875] |     sys_open();
  19.099 us [ 9875] |   } /* fopen */
            [ 9875] |   fclose() {
   3.380 us [ 9875] |     sys_close();
   9.720 us [ 9875] |   } /* fclose */
  37.051 us [ 9875] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        program = 't-' + self.name

        argument  = '-k -F main'
        argument += ' -P sys_open*@kernel'
        argument += ' -P sys_close*@kernel'

        return '%s %s %s' % (uftrace, argument, program)

    def fixup(self, cflags, result):
        uname = os.uname()

        result = result.replace(' sys_open', ' sys_openat')

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 4 and int(minor) >= 17:
            result = result.replace('sys_', '__x64_sys_')

        return result
