#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR  = 'xxx'
TDIR2 = 'yyy'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', serial=True, result="""
# DURATION    TID     FUNCTION
   1.088 us [18343] | __monstartup();
   0.640 us [18343] | __cxa_atexit();
            [18343] | main() {
            [18343] |   fopen() {
  86.790 us [18343] |     sys_open();
  89.018 us [18343] |   } /* fopen */
            [18343] |   fclose() {
  10.781 us [18343] |     sys_close();
  37.325 us [18343] |   } /* fclose */
 128.387 us [18343] | } /* main */
""")
        self.gen_port()

    recv_p = None

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        uftrace = TestBase.uftrace_cmd
        program = 't-' + self.name

        recv_cmd = '%s recv -d %s --port %s' % (uftrace, TDIR, self.port)
        self.recv_p = sp.Popen(recv_cmd.split())

        argument  = '-H %s -k -d %s --port %s' % ('localhost', TDIR2, self.port)
        argument += ' -N %s@kernel' % 'exit_to_usermode_loop'
        argument += ' -N %s@kernel' % '_*do_page_fault'

        record_cmd = '%s record %s %s' % (uftrace, argument, program)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s' % (TestBase.uftrace_cmd, os.path.join(TDIR, TDIR2))

    def post(self, ret):
        self.recv_p.terminate()
        sp.call(['rm', '-rf', TDIR])
        return ret

    def fixup(self, cflags, result):
        uname = os.uname()

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            result = result.replace('sys_', '__x64_sys_')

        return result.replace(' sys_open', ' sys_openat')
