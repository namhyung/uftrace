#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [16873] | main() {
            [16873] |   foo() {
            [16873] |     mem_alloc() {
   1.675 us [16873] |       malloc();
   6.867 us [16873] |     } /* mem_alloc */
            [16873] |     bar() {
   2.068 ms [16873] |       usleep();
   2.071 ms [16873] |     } /* bar */
   2.085 ms [16873] |   } /* foo */
   2.086 ms [16873] | } /* main */
""")

    def pre(self):
        record_cmd = '%s --no-pager record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -t 1ms -T mem_alloc@time=0 -d %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
