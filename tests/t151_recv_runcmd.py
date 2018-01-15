#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR = 'xxx'
TMPF = 'out'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   a() {
            [28141] |     b() {
            [28141] |       c() {
   0.753 us [28141] |         getpid();
   1.430 us [28141] |       } /* c */
   1.915 us [28141] |     } /* b */
   2.405 us [28141] |   } /* a */
   3.005 us [28141] | } /* main */
""")

    recv_p = None
    file_p = None

    def pre(self):
        self.file_p = open(TMPF, 'w+')
        recv_cmd = TestBase.uftrace_cmd.split() + ['recv', '-d', TDIR, '--run-cmd', TestBase.uftrace_cmd + ' replay']
        self.recv_p = sp.Popen(recv_cmd, stdout=self.file_p, stderr=self.file_p)

        record_cmd = '%s record -H %s %s' % (TestBase.uftrace_cmd, 'localhost', 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        # run replay at recv time and print the result now
        return 'cat %s' % TMPF

    def post(self, ret):
        self.recv_p.terminate()
        sp.call(['rm', '-rf', TDIR])
        self.file_p.close()
        sp.call(['rm', '-f', TMPF])
        return ret
