#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR  = 'xxx'
TDIR2 = 'yyy'

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

    def pre(self):
        recv_cmd = '%s recv -d %s' % (TestBase.uftrace_cmd, TDIR)
        self.recv_p = sp.Popen(recv_cmd.split())

        # recorded but not used
        record_cmd = '%s record -H %s %s' % (TestBase.uftrace_cmd, 'localhost', 't-abc')
        sp.call(record_cmd.split())

        # use this
        record_cmd = '%s record -H %s -d %s %s' % (TestBase.uftrace_cmd, 'localhost', TDIR2, 't-abc')
        sp.call(record_cmd.split())

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        import os.path
        return '%s replay -d %s' % (TestBase.uftrace_cmd, os.path.join(TDIR, TDIR2))

    def post(self, ret):
        self.recv_p.terminate()
        sp.call(['rm', '-rf', TDIR])
        return ret
