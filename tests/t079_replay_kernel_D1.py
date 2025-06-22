#!/usr/bin/env python3

import os
import subprocess as sp

from runtest import TestBase

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

        # Later version changed syscall routines
        major, minor, release = uname[2].split('.', 2)
        if uname[0] == 'Linux' and uname[4] == 'x86_64':
            if int(major) >= 6 and int(minor) >= 9:
                import re
                result = re.sub(r'sys_[^(]*', 'x64_sys_call', result)
            elif int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
                result = result.replace('sys_', '__x64_sys_')
        if uname[0] == 'Linux' and uname[4] == 'aarch64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 19):
            result = result.replace('sys_', '__arm64_sys_')

        return result.replace(' sys_open', ' sys_openat')
