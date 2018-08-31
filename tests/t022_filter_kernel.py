#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', """
# DURATION    TID     FUNCTION
            [20769] | main() {
   0.925 us [20769] |   getpid();
   2.089 us [20769] |   getppid();
   1.334 us [20769] |   getpgid();
   0.881 us [20769] |   getsid();
   1.234 us [20769] |   getuid();
            [20769] |   geteuid() {
   0.056 us [20769] |     sys_geteuid();
   1.178 us [20769] |   } /* geteuid */
   0.994 us [20769] |   getgid();
            [20769] |   getegid() {
   0.054 us [20769] |     sys_getegid();
   0.912 us [20769] |   } /* getegid */
  81.933 us [20769] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        uname = os.uname()

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 4 and int(minor) >= 17:
            self.result = """
# DURATION     TID     FUNCTION
            [ 20769] | main() {
            [ 20769] |   getpid() {
   0.794 us [ 20769] |     do_syscall_64();
   0.925 us [ 20769] |   } /* getpid */
            [ 20769] |   getppid() {
   1.578 us [ 20769] |     do_syscall_64();
   2.089 us [ 20769] |   } /* getppid */
            [ 20769] |   getpgid() {
   1.015 us [ 20769] |     do_syscall_64();
   1.334 us [ 20769] |   } /* getpgid */
            [ 20769] |   getsid() {
   0.483 us [ 20769] |     do_syscall_64();
   0.881 us [ 20769] |   } /* getsid */
            [ 20769] |   getuid() {
   1.002 us [ 20769] |     do_syscall_64();
   1.234 us [ 20769] |   } /* getuid */
            [ 20769] |   geteuid() {
   0.056 us [ 20769] |     do_syscall_64();
   1.178 us [ 20769] |   } /* geteuid */
            [ 20769] |   getgid() {
   0.829 us [ 20769] |     do_syscall_64();
   0.994 us [ 20769] |   } /* getgid */
            [ 20769] |   getegid() {
   0.054 us [ 20769] |     do_syscall_64();
   0.912 us [ 20769] |   } /* getegid */
  81.933 us [ 20769] | } /* main */
"""
            return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        program = 't-' + self.name
        uname   = os.uname()

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 4 and int(minor) >= 17:
            argument = "-k -F do_syscall*@kernel"
        else:
            argument = "-K -F sys_gete*@kernel"

        return '%s %s %s' % (uftrace, argument, program)
