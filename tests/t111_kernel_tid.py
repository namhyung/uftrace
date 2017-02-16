#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
# DURATION    TID     FUNCTION
            [ 1661] | main() {
            [ 1661] |   fork() {
   5.135 us [ 1661] |     sys_writev();
  32.391 us [ 1661] |     do_syscall_64();
 130.930 us [ 1661] |   } /* fork */
            [ 1661] |   wait() {
   7.074 us [ 1661] |     sys_wait4();
 691.873 us [ 1661] |   } /* wait */
            [ 1661] |   a() {
            [ 1661] |     b() {
            [ 1661] |       c() {
   4.234 us [ 1661] |         getpid();
   5.680 us [ 1661] |       } /* c */
   6.094 us [ 1661] |     } /* b */
   6.602 us [ 1661] |   } /* a */
 849.948 us [ 1661] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        record_cmd = '%s record -k -N %s@kernel -N %s@kernel -d %s %s' % \
                     (TestBase.ftrace, '*page_fault', 'smp_irq_work_interrupt', TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        import os.path
        t = 0
        for ln in open(os.path.join(TDIR, 'task.txt')):
            if not ln.startswith('TASK'):
                continue
            try:
                t = int(ln.split()[2].split('=')[1])
            except:
                pass
        if t == 0:
            return 'FAILED TO FIND TID'
        return '%s replay -k -d %s --tid %d' % (TestBase.ftrace, TDIR, t)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
