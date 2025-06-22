#!/usr/bin/env python3

import os

from runtest import TestBase

# there was a problem applying depth filter if it contains kernel functions
class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', serial=True, result="""
# DURATION    TID     FUNCTION
   0.714 us [ 4435] | __monstartup();
   0.349 us [ 4435] | __cxa_atexit();
            [ 4435] | main() {
            [ 4435] |   fopen() {
   6.413 us [ 4435] |     sys_open();
   7.037 us [ 4435] |   } /* fopen */
            [ 4435] |   fclose() {
   8.389 us [ 4435] |     sys_close();
   9.949 us [ 4435] |   } /* fclose */
  17.632 us [ 4435] | } /* main */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option  = '-K3 '
        self.option += '-T ^sys_@kernel,depth=1 '
        self.option += '-T ^__x64_@kernel,depth=1 '
        self.option += '-T ^__arm64_@kernel,depth=1 '
        self.option += '-T x64_sys_call@kernel,depth=1 '
        self.option += '-N exit_to_usermode_loop@kernel '
        self.option += '-N _*do_page_fault@kernel'

    def fixup(self, cflags, result):
        uname = os.uname()

        # Later version changed syscall routines
        major, minor, release = uname[2].split('.', 2)
        if uname[0] == 'Linux' and uname[4] == 'x86_64':
            if int(major) == 6 and int(minor) >= 9:
                import re
                result = re.sub(r'sys_[^( ]*', 'x64_sys_call', result)
            elif int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
                result = result.replace('sys_', '__x64_sys_')
        if uname[0] == 'Linux' and uname[4] == 'aarch64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 19):
            result = result.replace('sys_', '__arm64_sys_')

        return result.replace(' sys_open', ' sys_openat')
