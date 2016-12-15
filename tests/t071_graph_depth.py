#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
#
# function graph for 'main'
#

backtrace
================================
 backtrace #0: hit 1, time  17.930 us
   [0] main (0x4004f0)

calling functions
================================
  17.930 us : (1) main
   2.472 us :  +-(2) operator new
            :  | 
   1.106 us :  +-(1) ns::ns1::foo::foo
            :  | 
   4.968 us :  +-(1) ns::ns1::foo::bar
   2.788 us :  |  +-(1) ns::ns1::foo::bar1
   2.469 us :  |  | (1) ns::ns1::foo::bar2
   2.117 us :  |  | (1) ns::ns1::foo::bar3
            :  |  | 
   1.565 us :  |  +-(1) free
            :  | 
   3.924 us :  +-(2) operator delete
            :  | 
   0.092 us :  +-(1) ns::ns2::foo::foo
            :  | 
   1.917 us :  +-(1) ns::ns2::foo::bar
   1.220 us :     +-(1) ns::ns2::foo::bar1
   0.963 us :     | (1) ns::ns2::foo::bar2
   0.714 us :     | (1) ns::ns2::foo::bar3
            :     | 
   0.240 us :     +-(1) free
""")

    def pre(self):
        record_cmd = '%s --no-pager record -d %s %s' % (TestBase.ftrace, TDIR, 't-namespace')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s -D5 %s' % (TestBase.ftrace, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def sort(self, output):
        """ This function post-processes output of the test to be compared.
            It ignores blank and comment (#) lines and header lines.  """
        result = []
        mode = 0
        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#') or ln.startswith('='):
                continue
            if ln.startswith('backtrace'):
                mode = 1
                continue
            if ln.startswith('calling'):
                mode = 2
                continue
            if mode == 1:
                if ln.startswith(' backtrace #'):
                    result.append(ln.split(',')[0])  # remove time part
                if ln.startswith('   ['):
                    result.append(ln.split('(')[0])  # remove '(addr)' part
            if mode == 2:
                result.append(ln.split(':')[1])      # remove time part

        return '\n'.join(result)
