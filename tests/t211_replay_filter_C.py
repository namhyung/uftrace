#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION     TID     FUNCTION
            [ 30702] | main() {
            [ 30702] |   foo() {
   6.933 us [ 30702] |     mem_alloc();
   2.139 ms [ 30702] |   } /* foo */
   2.141 ms [ 30702] | } /* main */
""")

    def pre(self):
        uftrace = TestBase.uftrace_cmd
        options = '-d %s' % TDIR
        program = 't-' + self.name

        record_cmd = '%s record %s %s' % (uftrace, options, program)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '-d %s -C %s' % (TDIR, 'mem_alloc')

        return '%s replay %s' % (uftrace, options)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
