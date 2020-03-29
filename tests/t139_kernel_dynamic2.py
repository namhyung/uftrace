#!/usr/bin/env python

from runtest import TestBase
import os

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

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            return result.replace(' sys_open', ' __x64_sys_openat')
        else:
            return result.replace(' sys_open', ' sys_openat')
