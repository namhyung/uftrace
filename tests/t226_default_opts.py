#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep2', result="""
# DURATION     TID     FUNCTION
            [ 41487] | main() {
            [ 41487] |   foo() {
   5.107 ms [ 41487] |     usleep();
   8.220 ms [ 41487] |   } /* foo */
   9.336 ms [ 41487] | } /* main */
""")

    def pre(self):
        record_cmd = '%s record -d %s -t 2ms %s' % (TestBase.uftrace_cmd, TDIR, 't-sleep2')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s -t 4ms %s' % (TestBase.uftrace_cmd, 't-' + self.name)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
