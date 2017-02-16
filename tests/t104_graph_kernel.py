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
""", sort='graph')

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        record_cmd = '%s record -k -N %s@kernel -d %s %s' % \
                     (TestBase.ftrace, 'smp_irq_work_interrupt', TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -k -d %s %s' % (TestBase.ftrace, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
