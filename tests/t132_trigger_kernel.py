#!/usr/bin/env python

from runtest import TestBase
import os

# there was a problem applying depth filter if it contains kernel functions
class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', """
# DURATION    TID     FUNCTION
   0.714 us [ 4435] | __monstartup();
   0.349 us [ 4435] | __cxa_atexit();
            [ 4435] | main() {
            [ 4435] |   open() {
   6.413 us [ 4435] |     sys_open();
   7.037 us [ 4435] |   } /* open */
            [ 4435] |   close() {
   8.389 us [ 4435] |     sys_close();
   9.949 us [ 4435] |   } /* close */
  17.632 us [ 4435] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        # the -T option works on replay time and accept a regex
        # while -N option works on record time and accept a glob
        return '%s -K3 -T %s@kernel,depth=1 -N %s@kernel -N %s@kernel %s' % \
            (TestBase.ftrace, '^sys_', 'exit_to_usermode_loop', 'smp_irq_work_interrupt', 't-' + self.name)
