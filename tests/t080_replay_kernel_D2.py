#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR='xxx'

# there was a problem applying depth filter if it contains kernel functions
class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', """
# DURATION    TID     FUNCTION
   1.088 us [18343] | __monstartup();
   0.640 us [18343] | __cxa_atexit();
            [18343] | main() {
  89.018 us [18343] |   open();
  37.325 us [18343] |   close();
 128.387 us [18343] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        record_cmd = '%s --no-pager record -K3 -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -k -D2 -d %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
