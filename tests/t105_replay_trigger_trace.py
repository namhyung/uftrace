#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'trace', result="""
# DURATION    TID     FUNCTION
            [18219] | main() {
            [18219] |   foo() {
   2.093 ms [18219] |     bar();
   2.106 ms [18219] |   } /* foo */
   2.107 ms [18219] | } /* main */
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-trace')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s -t 5ms -T "bar@trace"' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
