#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
    1.152 ms   71.683 us           1  main
    1.080 ms    1.813 us           1  bar
    1.078 ms    2.892 us           1  usleep
    1.075 ms    1.075 ms           1  linux:schedule
   70.176 us   70.176 us           1  __monstartup   # ignore this
   37.525 us    1.137 us           2  foo
   36.388 us   36.388 us           6  loop
    1.200 us    1.200 us           1  __cxa_atexit   # and this too
""", sort='report')

    def pre(self):
        if not TestBase.check_dependency(self, 'perf_context_switch'):
            return TestBase.TEST_SKIP
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP

        options = '-d %s -E %s' % (TDIR, 'linux:schedule')
        record_cmd = '%s record %s %s' % (TestBase.uftrace_cmd, options, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report -d %s' % (TestBase.uftrace_cmd.split()[0], TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
