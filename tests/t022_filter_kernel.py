#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', """
# DURATION    TID     FUNCTION
            [20769] | main() {
   0.925 us [20769] |   getpid();
   2.089 us [20769] |   getppid();
   1.334 us [20769] |   getpgid();
   0.881 us [20769] |   getsid();
   1.234 us [20769] |   getuid();
            [20769] |   geteuid() {
   0.056 us [20769] |     sys_geteuid();
   1.178 us [20769] |   } /* geteuid */
   0.994 us [20769] |   getgid();
            [20769] |   getegid() {
   0.054 us [20769] |     sys_getegid();
   0.912 us [20769] |   } /* getegid */
  81.933 us [20769] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s -k -F "sys_gete*@kernel" %s' % (TestBase.uftrace_cmd, 't-getids')
