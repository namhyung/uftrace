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
  12.192 us [ 1661] |     __do_page_fault();
  10.982 us [ 1661] |     __do_page_fault();
   9.183 us [ 1661] |     __do_page_fault();
 130.930 us [ 1661] |   } /* fork */
  17.134 us [ 1661] |   __do_page_fault();
  12.813 us [ 1661] |   __do_page_fault();
   9.465 us [ 1661] |   __do_page_fault();
   3.187 us [ 1661] |   __do_page_fault();
   6.873 us [ 1661] |   __do_page_fault();
            [ 1661] |   wait() {
   6.508 us [ 1661] |     __do_page_fault();
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

        record_cmd = '%s --no-pager record -k -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
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
