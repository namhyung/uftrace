#!/usr/bin/env python3

import os.path
import subprocess as sp
import time

from runtest import TestBase

TDIR  = 'xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', serial=True, result="""
# DURATION    TID     FUNCTION
            [  395] | main() {
            [  395] |   foo() {
            [  395] |     mem_alloc() {
   1.328 us [  395] |       malloc();
   1.924 us [  395] |     } /* mem_alloc */
            [  395] |     bar() {
            [  395] |       usleep() {
   2.088 ms [  395] |         /* linux:schedule */
   2.105 ms [  395] |       } /* usleep */
   2.109 ms [  395] |     } /* bar */
            [  395] |     mem_free() {
   3.137 us [  395] |       free();
   3.783 us [  395] |     } /* mem_free */
   2.120 ms [  395] |   } /* foo */
   2.121 ms [  395] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_dependency(self, 'perf_context_switch'):
            return TestBase.TEST_SKIP
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP

        self.gen_port()
        self.subcmd = 'recv'
        self.option = '-d %s --port %s' % (TDIR, self.port)
        self.exearg = ''

        recv_cmd = TestBase.runcmd(self)
        self.pr_debug('prerun command: ' + recv_cmd)
        self.recv_p = sp.Popen(recv_cmd.split())

        time.sleep(0.1)

        self.subcmd  = 'record'
        self.option  = '--host %s --port %s ' % ('localhost', self.port)
        self.option += '-E %s' % 'linux:schedule'
        self.exearg  = 't-' + self.name

        record_cmd = TestBase.runcmd(self)
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-d ' + os.path.join(TDIR, 'uftrace.data')
        self.exearg = ''

    def runcmd(self):
        cmd = TestBase.runcmd(self)
        return cmd.replace('--no-event', '')

    def postrun(self, ret):
        self.recv_p.terminate()
        return ret
