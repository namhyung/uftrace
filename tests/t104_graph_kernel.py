#!/usr/bin/env python3

import os
import subprocess as sp

from runtest import TestBase

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

        # Later versions changed syscall routines
        major, minor, release = uname[2].split('.', 2)
        if uname[0] == 'Linux' and uname[4] == 'x86_64':
            if int(major) == 6 and int(minor) >= 9:
                import re
                result = re.sub(r'sys_get[a-z]*', 'x64_sys_call', result)
            elif int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
                result = result.replace('sys_get', '__x64_sys_get')
        if uname[0] == 'Linux' and uname[4] == 'aarch64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 19):
            result = result.replace('sys_get', '__arm64_sys_get')

        return result
