#!/usr/bin/env python3

import os.path
import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    """Add and remove opt-in and opt-out filters at runtime from the agent.

    The target runs a loop, and starts with leaf function c() filtered out. We
    remove the filter, expecting c() to appear in the trace. Then we apply two
    filters, and remove them one by one.
    """

    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
            [ 24808] | main() {
            [ 24808] |   func() {
            [ 24808] |     a() {
   2.115 ms [ 24808] |       b();
   3.178 ms [ 24808] |     } /* a */
   3.179 ms [ 24808] |   } /* func */
            [ 24808] |   func() {
            [ 24808] |     a() {
            [ 24808] |       b() {
   1.058 ms [ 24808] |         c();
   2.122 ms [ 24808] |       } /* b */
   3.195 ms [ 24808] |     } /* a */
   3.196 ms [ 24808] |   } /* func */
   2.124 ms [ 24808] |   b();
            [ 24808] |   func() {
            [ 24808] |     a() {
   2.135 ms [ 24808] |       b();
   3.207 ms [ 24808] |     } /* a */
   3.208 ms [ 24808] |   } /* func */
            [ 24808] |   func() {
            [ 24808] |     a() {
            [ 24808] |       b() {
   1.068 ms [ 24808] |         c();
   2.137 ms [ 24808] |       } /* b */
   3.206 ms [ 24808] |     } /* a */
   3.206 ms [ 24808] |   } /* func */
  58.216 ms [ 24808] | } /* main */
""")


    def client_send_command(self, pid, option):
        self.subcmd = 'live'
        self.option = '-p %d %s' % (pid, option)
        self.exearg = ''
        client_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + client_cmd)
        client_p = sp.run(client_cmd.split())
        return client_p.returncode

    def prerun(self, timeout):
        self.subcmd = 'record'
        self.option  = '--keep-pid'
        self.option += ' --no-libcall'
        self.option += ' --agent'
        self.option += ' -N c'
        self.exearg = 't-' + self.name
        record_cmd  = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        # bufsize=0 to write characters one by one
        record_p = sp.Popen(record_cmd.split(), stdin=sp.PIPE, stderr=sp.PIPE, bufsize=0)

        while not os.path.exists("/tmp/uftrace/%d.socket" % record_p.pid):
            sleep(.01)

        if self.client_send_command(record_p.pid, '-F c@clear') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-F b -N c') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-F b@clear') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-F c@clear') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        record_p.stdin.close()
        record_p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''
