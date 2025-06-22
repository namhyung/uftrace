#!/usr/bin/env python3

import os
import subprocess as sp

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', serial=True, result="""
# DURATION    TID     FUNCTION
            [ 1661] | main() {
            [ 1661] |   fork() {
   5.135 us [ 1661] |     sys_writev();
  32.391 us [ 1661] |     sys_clone();
 130.930 us [ 1661] |   } /* fork */
            [ 1661] |   wait() {
   7.074 us [ 1661] |     sys_wait4();
 691.873 us [ 1661] |   } /* wait */
            [ 1661] |   a() {
            [ 1661] |     b() {
            [ 1661] |       c() {
   4.234 us [ 1661] |         getpid();
   5.680 us [ 1661] |       } /* c */
   6.094 us [ 1661] |     } /* b */
   6.602 us [ 1661] |   } /* a */
 849.948 us [ 1661] | } /* main */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        self.subcmd  = 'record'
        self.option  = '-k --match glob '
        self.option += '-N *page_fault@kernel'

        record_cmd = self.runcmd()
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        t = 0
        for ln in open(os.path.join('uftrace.data', 'task.txt')):
            if not ln.startswith('TASK'):
                continue
            try:
                t = int(ln.split()[2].split('=')[1])
            except:
                pass
        if t == 0:
            self.subcmd = 'FAILED TO FIND TID'
            return

        self.subcmd = 'replay'
        self.option = '-k --tid %d' % t

    def fixup(self, cflags, result):
        result = result.replace("            [ 1661] |   fork() {",
"""\
            [ 1661] |   fork() {
   5.135 us [ 1661] |     sys_getpid();""")

        result = result.replace("   4.234 us [ 1661] |         getpid();",
"""\
            [ 1661] |         getpid() {
   3.328 us [ 1661] |           sys_getpid();
   4.234 us [ 1661] |         } /* getpid */""")

        uname = os.uname()

        # Later version changed syscall routines
        major, minor, release = uname[2].split('.', 2)
        if uname[0] == 'Linux' and uname[4] == 'x86_64':
            if int(major) == 6 and int(minor) >= 9:
                import re
                result = re.sub(r'sys_[^( ]*', 'x64_sys_call', result)
            elif int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
                result = result.replace('sys_', '__x64_sys_')

        return result
