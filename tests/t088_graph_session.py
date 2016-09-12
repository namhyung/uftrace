#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'forkexec', result="""
#
# function graph for 'main' (session: ee242b9985a2975d)
#

backtrace
================================
 backtrace #0: hit 1, time   7.865 us
   [0] __gmon_start__ (0)
   [1] c (0x400680)
   [2] main (0x400510)

calling functions
================================
   7.865 us : (1) main
   1.506 us :  +-(1) atoi
            :  | 
   2.988 us :  +-(1) a
   2.705 us :    (1) b
   2.271 us :    (1) c
   0.657 us :    (1) getpid

#
# function graph for 'main' (session: 1dc307633af856ad)
#

backtrace
================================
 backtrace #0: hit 1, time   3.433 ms
   [0] main (0x4007ed)

calling functions
================================
   3.433 ms : (1) main
   9.814 us :  +-(1) readlink
            :  | 
   0.922 us :  +-(1) strrchr
            :  | 
   1.737 us :  +-(1) strcpy
            :  | 
 114.506 us :  +-(1) fork
            :  | 
   3.289 ms :  +-(1) waitpid
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s %s' % (TestBase.ftrace, TDIR, FUNC)

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
                mode = 1  # it seems to be broken in this case
                continue
            if ln.startswith('calling'):
                mode = 2
                continue
            if mode == 1:
                pass      # compare function graph part only
            if mode == 2:
                result.append(ln.split(':')[1])      # remove time part

        return '\n'.join(result)
