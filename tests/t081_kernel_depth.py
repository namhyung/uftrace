#!/usr/bin/env python3

import os

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', serial=True, result="""
# DURATION    TID     FUNCTION
   1.540 us [27711] | __monstartup();
   1.089 us [27711] | __cxa_atexit();
            [27711] | main() {
            [27711] |   fopen() {
            [27711] |     sys_open() {
  12.732 us [27711] |       do_sys_open();
  14.039 us [27711] |     } /* sys_open */
  17.193 us [27711] |   } /* fopen */
            [27711] |   fclose() {
            [27711] |     sys_close() {
   0.591 us [27711] |       __close_fd();
   1.429 us [27711] |     } /* sys_close */
   8.028 us [27711] |   } /* fclose */
  26.938 us [27711] | } /* main */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option  = '-k --kernel-depth=2 --match glob '
        self.option += '-N exit_to_usermode_loop@kernel '
        self.option += '-N *do_page_fault@kernel'

    def fixup(self, cflags, result):
        uname = os.uname()

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.', 2)
        if uname[0] == 'Linux' and uname[4] == 'x86_64':
            if int(major) == 6 and int(minor) >= 9:
                import re
                result = re.sub(r' sys_[^( ]*', ' x64_sys_call', result)
                result = result.replace('do_sys_open', '__x64_sys_open')
                result = result.replace('__close_fd', '__x64_sys_close')
            elif int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
                result = result.replace(' sys_', ' __x64_sys_')
        if uname[0] == 'Linux' and uname[4] == 'aarch64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 19):
            result = result.replace(' sys_', ' __arm64_sys_')

        return result.replace('sys_open', 'sys_openat')
