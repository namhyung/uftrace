#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
  849.948 us   20.543 us           2  main
  691.873 us  691.873 us           1  wait
  130.930 us  130.930 us           2  fork
   10.942 us    0.880 us           2  a
   10.062 us    0.756 us           2  b
    3.626 us    1.612 us           1  c
    1.568 us    1.568 us           1  __monstartup
    1.140 us    1.140 us           1  __cxa_atexit
""", sort='report')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report -d %s -D 3' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
