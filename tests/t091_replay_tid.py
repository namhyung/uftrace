#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
# DURATION    TID     FUNCTION
            [ 1661] | main() {
 130.930 us [ 1661] |   fork();
 691.873 us [ 1661] |   wait();
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
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
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
        return '%s replay -d %s -F main --tid %d' % (TestBase.ftrace, TDIR, t)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
