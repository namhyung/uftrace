#!/usr/bin/env python3

import os.path
import subprocess as sp
import time

from runtest import TestBase

TDIR  = 'xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   a() {
            [28141] |     b() {
            [28141] |       c() {
   0.753 us [28141] |         getpid();
   1.430 us [28141] |       } /* c */
   1.915 us [28141] |     } /* b */
   2.405 us [28141] |   } /* a */
   3.005 us [28141] | } /* main */
""")

    def prerun(self, timeout):
        self.gen_port()

        self.subcmd = 'recv'
        self.option = '-d %s --port %s' % (TDIR, self.port)
        self.exearg = ''
        recv_cmd = self.runcmd()
        self.pr_debug("prerun command: " + recv_cmd)
        self.recv_p = sp.Popen(recv_cmd.split())

        time.sleep(0.1)

        self.subcmd = 'record'
        self.option = '--host %s --port %s' % ('localhost', self.port)
        self.exearg = 't-' + self.name
        record_cmd = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-d ' + os.path.join(TDIR, 'uftrace.data')
        self.exearg = ''

    def postrun(self, ret):
        self.recv_p.terminate()
        return ret
