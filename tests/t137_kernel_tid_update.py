#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork2', serial=True, result="""
# DURATION    TID     FUNCTION
            [19227] | main() {
 328.451 us [19227] |   fork();
            [19227] |   wait() {
            [19231] |   } /* fork */
            [19231] |   open() {
  17.068 us [19231] |     sys_open();
  21.964 us [19231] |   } /* open */
            [19231] |   close() {
   2.537 us [19231] |     sys_close();
   7.057 us [19231] |   } /* close */
            [19231] | } /* main */
  40.601 ms [19227] |   } /* wait */
            [19227] |   open() {
  30.832 us [19227] |     sys_open();
  37.121 us [19227] |   } /* open */
            [19227] |   close() {
   2.950 us [19227] |     sys_close();
   9.520 us [19227] |   } /* close */
  41.010 ms [19227] | } /* main */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option  = '-k -F main '
        self.option += '-F sys_open*@kernel '
        self.option += '-F sys_close*@kernel'

    def fixup(self, cflags, result):
        uname = os.uname()

        result = result.replace(' sys_open', ' sys_openat')

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            result = result.replace('sys_', '__x64_sys_')

        return result
