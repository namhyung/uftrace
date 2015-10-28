#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', """
# DURATION    TID     FUNCTION
            [20769] | main() {
   0.925 us [20769] |   getpid();
            [20769] |   getppid() {
   0.346 us [20769] |     sys_getppid();
   2.089 us [20769] |   } /* getppid */
   1.334 us [20769] |   getpgid();
   0.881 us [20769] |   getsid();
            [20769] |   getuid() {
   0.092 us [20769] |     sys_getuid();
   1.234 us [20769] |   } /* getuid */
            [20769] |   geteuid() {
   0.056 us [20769] |     sys_geteuid();
   1.178 us [20769] |   } /* geteuid */
            [20769] |   getgid() {
   0.057 us [20769] |     sys_getgid();
   0.994 us [20769] |   } /* getgid */
            [20769] |   getegid() {
   0.054 us [20769] |     sys_getegid();
   0.912 us [20769] |   } /* getegid */
  81.933 us [20769] | } /* main */
""")

    def runcmd(self):
        return 'sudo %s -k -F "sys_get*@kernel" %s' % (TestBase.ftrace, 't-getids')
