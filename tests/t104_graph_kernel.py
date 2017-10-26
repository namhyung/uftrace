#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', result="""
# Function Call Graph for 'main' (session: 59268c360e3c1bd6)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time  24.837 us
   [0] main (0x400893)

========== FUNCTION CALL GRAPH ==========
  24.837 us : (1) main
   0.860 us :  +-(1) getpid
            :  | 
   3.130 us :  +-(1) getppid
   1.080 us :  | (1) sys_getppid
            :  | 
   2.926 us :  +-(1) getpgid
   0.834 us :  | (1) sys_getpgid
            :  | 
   2.393 us :  +-(1) getsid
   0.750 us :  | (1) sys_getsid
            :  | 
   2.030 us :  +-(1) getuid
   0.660 us :  | (1) sys_getuid
            :  | 
   2.074 us :  +-(1) geteuid
   0.510 us :  | (1) sys_geteuid
            :  | 
   4.391 us :  +-(1) getgid
   0.696 us :  | (1) sys_getgid
            :  | 
   4.223 us :  +-(1) getegid
   1.710 us :    (1) sys_getegid
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

    def fixup(self, cflags, result):
        return result.replace("   1.123 us :  +-(1) getpid",
"""   1.123 us :  +-(1) getpid
0.738 us :  | (1) sys_getpid""")
