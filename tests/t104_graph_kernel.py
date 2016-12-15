#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', result="""
#
# function graph for 'main' (session: 771f183fd824f3a3)
#

backtrace
================================
 backtrace #0: hit 1, time  17.436 us
   [0] main (0x4006c0)

calling functions
================================
  17.436 us : (1) main
   1.123 us :  +-(1) getpid
            :  | 
   1.838 us :  +-(1) getppid
   0.738 us :  | (1) sys_getppid
            :  | 
   1.919 us :  +-(1) getpgid
   0.629 us :  | (1) sys_getpgid
            :  | 
   1.711 us :  +-(1) getsid
   0.496 us :  | (1) sys_getsid
            :  | 
   1.353 us :  +-(1) getuid
   0.361 us :  | (1) sys_getuid
            :  | 
   1.451 us :  +-(1) geteuid
   0.470 us :  | (1) sys_geteuid
            :  | 
   1.456 us :  +-(1) getgid
   0.401 us :  | (1) sys_getgid
            :  | 
   1.360 us :  +-(1) getegid
   0.346 us :    (1) sys_getegid
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        record_cmd = '%s --no-pager record -k -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -k -d %s %s' % (TestBase.ftrace, TDIR, FUNC)

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
