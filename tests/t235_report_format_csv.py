#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
Total time, Self time, Calls, Function
11450100, 762665, 1, main
10379365, 270708, 1, bar
10108657, 15785, 1, usleep
308070, 2136, 2, foo
305934, 305934, 6, loop
""")

    def pre(self):
	record_cmd = '%s record -F main --no-event -d %s %s' \
			% (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
	return '%s report --format=csv -d %s' % (TestBase.uftrace_cmd, TDIR)

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
            line = ln.split(',')
            if line[0] == 'Total time':
                continue
            result.append('%s %s' % (line[2], line[3]))

        return '\n'.join(result)
