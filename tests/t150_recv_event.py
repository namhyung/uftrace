#!/usr/bin/env python3

import os.path
import subprocess as sp
import time

from runtest import TestBase

TDIR  = 'xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sdt', """
# DURATION    TID     FUNCTION
   9.392 us [28141] | __monstartup();
  12.912 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   foo() {
            [28141] |     /* uftrace:event */
   2.896 us [28141] |   } /* foo */
   3.017 us [28141] | } /* main */
""")

    def prerun(self, timeout):
        self.gen_port()

        self.subcmd = 'recv'
        self.option = '-d %s --port %s' % (TDIR, self.port)
        self.exearg = ''
        recv_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + recv_cmd)
        self.recv_p = sp.Popen(recv_cmd.split())

        time.sleep(0.1)

        self.subcmd = 'record'
        self.option = '--host %s --port %s -E uftrace:event' % ('localhost', self.port)
        self.exearg = 't-' + self.name
        record_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())

        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        if not TestBase.check_arch_sdt_support(self):
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-E uftrace:event -d ' + os.path.join(TDIR, 'uftrace.data')
        self.exearg = ''

    def postrun(self, ret):
        self.recv_p.terminate()
        return ret
