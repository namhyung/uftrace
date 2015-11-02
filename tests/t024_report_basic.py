#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
  Total time   Self time  Nr. called  Function
  ==========  ==========  ==========  ====================================
    1.152 ms   71.683 us           1  main
    1.080 ms    1.813 us           1  bar
    1.078 ms    1.078 ms           1  usleep
   70.176 us   70.176 us           1  __monstartup   # ignore this
   37.525 us    1.137 us           2  foo
   36.388 us   36.388 us           6  loop
    1.200 us    1.200 us           1  __cxa_atexit   # and this too
""")

    def pre(self):
        record_cmd = '%s record -f %s %s' % (TestBase.ftrace, TDIR, 't-sort')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report -f %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue
            line = ln.split()
            if line[0] == 'Total':
                continue
            if line[0].startswith('='):
                continue
            # A report line consists of following data
            # [0]         [1]   [2]        [3]   [4]     [5]
            # total_time  unit  self_time  unit  called  function
            if line[5].startswith('__'):
                continue
            result.append('%s %s' % (line[4], line[5]))

        return '\n'.join(result)
