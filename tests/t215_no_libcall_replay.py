#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
# DURATION     TID     FUNCTION
            [ 73755] | main() {
   0.236 us [ 73755] |   foo();
            [ 73755] |   sighandler() {
   0.144 us [ 73755] |     bar();
   0.734 us [ 73755] |   } /* sighandler */
   0.117 us [ 73755] |   foo();
  18.227 us [ 73755] | } /* main */
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay --no-libcall -d %s' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
