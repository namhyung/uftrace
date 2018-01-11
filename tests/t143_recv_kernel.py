#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR  = 'xxx'
TDIR2 = 'yyy'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', """
# DURATION    TID     FUNCTION
   1.088 us [18343] | __monstartup();
   0.640 us [18343] | __cxa_atexit();
            [18343] | main() {
            [18343] |   fopen() {
  86.790 us [18343] |     sys_open();
  89.018 us [18343] |   } /* fopen */
            [18343] |   fclose() {
  10.781 us [18343] |     sys_close();
  21.980 us [18343] |     exit_to_usermode_loop();
  37.325 us [18343] |   } /* fclose */
 128.387 us [18343] | } /* main */
""")

    recv_p = None

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        recv_cmd = '%s recv -d %s' % (TestBase.uftrace_cmd, TDIR)
        self.recv_p = sp.Popen(recv_cmd.split())

        record_cmd = '%s record -H %s -k -N %s@kernel -d %s %s' % \
                     (TestBase.uftrace_cmd, 'localhost', 'smp_irq_work_interrupt', TDIR2, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s' % (TestBase.uftrace_cmd, os.path.join(TDIR, TDIR2))

    def post(self, ret):
        self.recv_p.terminate()
        sp.call(['rm', '-rf', TDIR])
        return ret

    def fixup(self, cflags, result):
        return result.replace('sys_open', 'sys_openat')
