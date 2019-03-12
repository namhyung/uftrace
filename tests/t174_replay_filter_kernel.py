#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', serial=True, result="""
# DURATION    TID     FUNCTION
            [18343] | main() {
            [18343] |   fopen() {
  86.790 us [18343] |     sys_open();
  89.018 us [18343] |   } /* fopen */
  37.325 us [18343] |   fclose();
 128.387 us [18343] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        uftrace  = TestBase.uftrace_cmd
        options  = '-k -d ' + TDIR
        program  = 't-' + self.name

        record_cmd = '%s record %s %s' % (uftrace, options, program)
        sp.call(record_cmd.split())

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        uname = os.uname()

        kfunc = 'sys_open*@kernel'

        argument = '-F main -D2 -F %s -d %s' % (kfunc, TDIR)
        return '%s replay %s' % (uftrace, argument)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def fixup(self, cflags, result):
        uname = os.uname()

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 4 and int(minor) >= 17:
            result = result.replace('sys_', '__x64_sys_')

        return result.replace(' sys_open', ' sys_openat')
