#!/usr/bin/env python3

import os.path
import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    """Test changing the tracing depth in the target from the agent.

    The target itself has an original depth limit of 4. We decrease the depth to
    2 and then increase the depth to 5."""

    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
            [ 14634] | main() {
            [ 14634] |   func() {
            [ 14634] |     a() {
   0.135 us [ 14634] |       b();
   0.524 us [ 14634] |     } /* a */
   0.732 us [ 14634] |   } /* func */
   0.279 us [ 14634] |   func();
            [ 14634] |   func() {
            [ 14634] |     a() {
            [ 14634] |       b() {
   0.074 us [ 14634] |         c();
   0.674 us [ 14634] |       } /* b */
   0.874 us [ 14634] |     } /* a */
   1.098 us [ 14634] |   } /* func */
  37.807 ms [ 14634] | } /* main */
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
        self.option += ' --agent'
        self.option += ' --no-libcall'
        self.option += ' -D 4'
        self.exearg = 't-' + self.name
        record_cmd  = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        # bufsize=0 to write characters one by one
        record_p = sp.Popen(record_cmd.split(), stdin=sp.PIPE, stderr=sp.PIPE, bufsize=0)

        while not os.path.exists("/tmp/uftrace/%d.socket" % record_p.pid):
            sleep(.01)

        if self.client_send_command(record_p.pid, '--depth=2') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '--depth=5') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        record_p.stdin.close()
        record_p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''
