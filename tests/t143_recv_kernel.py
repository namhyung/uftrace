#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import random
import os

TDIR  = 'xxx'

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
        self.recv_p = None

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        self.gen_port()

        self.subcmd = 'recv'
        self.option = '-d %s --port %s' % (TDIR, self.port)
        self.exearg = ''
        recv_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + recv_cmd)
        self.recv_p = sp.Popen(recv_cmd.split())

        self.dirname = 'dir-%d' % random.randint(100000, 999999)
        self.subcmd = 'record'
        self.option = '--host %s --port %s -d %s' % ('localhost', self.port, self.dirname)
        self.exearg = 't-' + self.name
        record_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-d %s' % os.path.join(TDIR, self.dirname)

    def postrun(self, ret):
        self.recv_p.terminate()
        return ret

    def fixup(self, cflags, result):
        uname = os.uname()

        # Linux v4.17 (x86_64) changed syscall routines
        major, minor, release = uname[2].split('.')
        if uname[0] == 'Linux' and uname[4] == 'x86_64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
            result = result.replace('sys_', '__x64_sys_')

        return result.replace(' sys_open', ' sys_openat')
