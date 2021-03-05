#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', serial=True, result="""
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

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        self.subcmd = 'record'
        self.option = '-k'
        self.exearg = 't-' + self.name

        record_cmd = self.runcmd()
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'graph'
        self.option = '-k'
        self.exearg = 'main'

    def fixup(self, cflags, result):
        uname = os.uname()

        result = result.replace("(1) getpid",
"""(1) getpid
   0.738 us :  | (1) sys_getpid""")

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            result = result.replace('sys_get', '__x64_sys_get')

        return result
