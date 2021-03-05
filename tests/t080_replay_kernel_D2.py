#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR='xxx'

# there was a problem applying depth filter if it contains kernel functions
class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', serial=True, result="""
# DURATION    TID     FUNCTION
   1.088 us [18343] | __monstartup();
   0.640 us [18343] | __cxa_atexit();
            [18343] | main() {
  89.018 us [18343] |   fopen();
  37.325 us [18343] |   fclose();
 128.387 us [18343] | } /* main */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        self.subcmd = 'record'
        self.option = '-K3 -N %s@kernel' % 'smp_irq_work_interrupt'
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-k -D2'
