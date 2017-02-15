#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [13256] | main() {
            [13256] |   foo() {
            [13256] |     mem_alloc() {
   1.000 us [13256] |       malloc();
   1.769 us [13256] |     } /* mem_alloc */
            [13256] |     bar() {
   2.073 ms [13256] |       usleep();
   2.075 ms [13256] |     } /* bar */
   2.084 ms [13256] |   } /* foo */
   2.085 ms [13256] | } /* main */
""")

    def pre(self):
        record_cmd = "%s --no-pager record -d %s %s" % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -t 1ms -T malloc@trace -d %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
