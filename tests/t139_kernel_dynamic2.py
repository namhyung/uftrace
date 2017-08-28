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
   9.720 us [ 9875] |   fclose();
  37.051 us [ 9875] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    # check syscall name would corrected (for SyS_ prefix)
    def runcmd(self):
        return '%s -k -P %s %s openclose' % \
            (TestBase.ftrace, 'sys_open@kernel', 't-' + self.name)
