#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
  Total time   Self time       Calls  Function [Source]
  ==========  ==========  ==========  ====================
    4.362 us    0.212 us           1  main [xxx/uftrace/tests/s-libmain.c:16]
    4.150 us    1.713 us           1  foo [xxx/uftrace/tests/s-libmain.c:11]
    1.804 us    0.186 us           1  lib_a [xxx/uftrace/tests/s-lib.c:10]
    1.618 us    0.980 us           1  lib_b [xxx/uftrace/tests/s-lib.c:15]
    0.638 us    0.638 us           1  lib_c [xxx/uftrace/tests/s-lib.c:20]
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        if TestBase.build_libabc(self, cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-libmain.c',
                                      ['libabc_test_lib.so'],
                                      cflags, ldflags)

    def prepare(self):
        self.subcmd = 'record'
        self.option = '--srcline --no-libcall'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--srcline'

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
            # [0]         [1]   [2]        [3]   [4]     [5]       [6]
            # total_time  unit  self_time  unit  called  function  srcline
            if line[-1].startswith('__'):
                continue

            if len(line) < 7 :
                result.append('%s %s' % (line[-2], line[-1]))
            else :
                result.append('%s %s %s' % (line[-3], line[-2], line[-1][1:-1].split('/')[-1]))

        return '\n'.join(result)
