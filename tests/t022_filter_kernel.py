#!/usr/bin/env python3

import os

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', serial=True, result="""
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

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option = "-k -F sys_gete.*@kernel"

    def fixup(self, cflags, result):
        uname = os.uname()
        # Later version changed syscall routines
        major, minor, release = uname[2].split('.', 2)
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            result = result.replace('sys_gete', '__x64_sys_gete')
        if uname[0] == 'Linux' and uname[4] == 'aarch64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 19):
            result = result.replace('sys_gete', '__arm64_sys_gete')

        return result
