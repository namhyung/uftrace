#!/usr/bin/env python3

import os

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', serial=True, result="""
# DURATION    TID     FUNCTION
            [ 9875] | main() {
            [ 9875] |   fopen() {
  14.416 us [ 9875] |     sys_open();
  19.099 us [ 9875] |   } /* fopen */
   9.720 us [ 9875] |   fclose();
  37.051 us [ 9875] | } /* main */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    # check syscall name would corrected (for SyS_ prefix)
    def setup(self):
        self.option = "-k -P '_*sys_open@kernel'"

    def fixup(self, cflags, result):
        uname = os.uname()

        return result.replace(' sys_open', ' sys_openat')

        # Later version changed syscall routines
        major, minor, release = uname[2].split('.', 2)
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            return result.replace(' sys_', ' __x64_sys_')
        if uname[0] == 'Linux' and uname[4] == 'aarch64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 19):
            return result.replace('sys_', '__arm64_sys_')
