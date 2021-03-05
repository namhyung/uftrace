#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', serial=True, result="""
# DURATION    TID     FUNCTION
   1.088 us [18343] | __monstartup();
   0.640 us [18343] | __cxa_atexit();
            [18343] | main() {
            [18343] |   fopen() {
  86.790 us [18343] |     sys_open();
  89.018 us [18343] |   } /* fopen */
            [18343] |   fclose() {
  10.781 us [18343] |     sys_close();
  37.325 us [18343] |   } /* fclose */
 128.387 us [18343] | } /* main */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        self.subcmd  = 'record'
        self.option  = '-K3 '
        self.option += '-N %s@kernel ' % 'exit_to_usermode_loop'
        self.option += '-N %s@kernel' % '_*do_page_fault'

        record_cmd = self.runcmd()
        sp.call(record_cmd.split())

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-k -D3'

    def fixup(self, cflags, result):
        uname = os.uname()

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            result = result.replace('sys_', '__x64_sys_')

        return result.replace(' sys_open', ' sys_openat')
