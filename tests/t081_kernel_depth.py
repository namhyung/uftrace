#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', """
# DURATION    TID     FUNCTION
   1.540 us [27711] | __monstartup();
   1.089 us [27711] | __cxa_atexit();
            [27711] | main() {
            [27711] |   open() {
            [27711] |     sys_open() {
  12.732 us [27711] |       do_sys_open();
  14.039 us [27711] |     } /* sys_open */
  17.193 us [27711] |   } /* open */
            [27711] |   close() {
            [27711] |     sys_close() {
   0.591 us [27711] |       __close_fd();
   1.429 us [27711] |     } /* sys_close */
   8.028 us [27711] |   } /* close */
  26.938 us [27711] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s -k --kernel-depth=2 -N %s@kernel %s' % \
            (TestBase.ftrace, 'exit_to_usermode_loop', 't-' + self.name)
