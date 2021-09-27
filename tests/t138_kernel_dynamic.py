#!/usr/bin/env python

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
            [ 9875] |   fclose() {
   3.380 us [ 9875] |     sys_close();
   9.720 us [ 9875] |   } /* fclose */
  37.051 us [ 9875] | } /* main */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option  = '-k -F main '
        self.option += '-P sys_open*@kernel '
        self.option += '-P sys_close*@kernel'

    def fixup(self, cflags, result):
        uname = os.uname()

        result = result.replace(' sys_open', ' sys_openat')

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            result = result.replace('sys_', '__x64_sys_')

        return result
