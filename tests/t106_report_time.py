#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
    2.103 ms    0.910 us           1  main
    2.102 ms   18.787 us           1  foo
    2.084 ms    4.107 us           1  bar
    2.080 ms    2.080 ms           1  usleep
""", sort='report')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report -t 1ms -d %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
