#!/usr/bin/env python

import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    """Test changing the time threshold in the target from the agent.

    The target is started with the '--delay' option so calls to a(), b() and c()
    include a 1ms sleep delay. The original threshold is 2ms. We decrease it to
    1ms and then increase it to 3ms.
    """

    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
            [  6314] | main() {
            [  6314] |   func() {
            [  6314] |     a() {
   2.134 ms [  6314] |       b();
   3.203 ms [  6314] |     } /* a */
   3.203 ms [  6314] |   } /* func */
            [  6314] |   func() {
            [  6314] |     a() {
            [  6314] |       b() {
   1.112 ms [  6314] |         c();
   2.121 ms [  6314] |       } /* b */
   3.186 ms [  6314] |     } /* a */
   3.187 ms [  6314] |   } /* func */
            [  6314] |   func() {
   3.207 ms [  6314] |     a();
   3.209 ms [  6314] |   } /* func */
  51.265 ms [  6314] | } /* main */
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
        self.option += ' -t 2ms'
        self.exearg = 't-' + self.name
        self.exearg += ' --delay' # add 1ms sleep to inner func calls
        record_cmd  = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        # bufsize=0 to write characters one by one
        record_p = sp.Popen(record_cmd.split(), stdin=sp.PIPE, stderr=sp.PIPE, bufsize=0)

        sleep(.05)              # time for the agent to start

        if self.client_send_command(record_p.pid, '--time-filter=1ms') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '--time-filter=3ms') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        record_p.stdin.close()
        record_p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        # NOTE See https://github.com/namhyung/uftrace/issues/1627
        # $uftrace dump shows the right output without the following line
        self.option += ' -t 1ms'
        self.exearg = ''
