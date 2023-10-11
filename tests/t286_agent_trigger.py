#!/usr/bin/env python3

import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    """Add and remove triggers at runtime from the client.

    The target runs a loop and waits for input from this script. The agent is
    enabled. Calls to a(), b() and c() include a sleep period so we can test time
    filters.

    The client adds then removes a depth filter. Then adds a time filter. And
    adds then removes an opt-out filter. """

    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
            [  6999] | main() {
            [  6999] |   func() {
            [  6999] |     a() {
            [  6999] |       b() {
   1.056 ms [  6999] |         c();
   2.113 ms [  6999] |       } /* b */
   3.175 ms [  6999] |     } /* a */
   3.175 ms [  6999] |   } /* func */
            [  6999] |   func() {
            [  6999] |     a() {
   2.110 ms [  6999] |       b();
   3.181 ms [  6999] |     } /* a */
   3.182 ms [  6999] |   } /* func */
            [  6999] |   func() {
   3.178 ms [  6999] |     a();
   3.179 ms [  6999] |   } /* func */
   3.177 ms [  6999] |   func();
            [  6999] |   func() {
            [  6999] |     a() {
            [  6999] |       b() {
   1.057 ms [  6999] |         c();
   2.119 ms [  6999] |       } /* b */
   3.185 ms [  6999] |     } /* a */
   3.185 ms [  6999] |   } /* func */
  55.835 ms [  6999] | } /* main */
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
        self.exearg  = 't-' + self.name
        self.exearg += ' --delay'
        record_cmd  = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        # bufsize=0 to write characters one by one
        record_p = sp.Popen(record_cmd.split(), stdin=sp.PIPE, stderr=sp.PIPE, bufsize=0)

        sleep(.05)              # time for the agent to start

        if self.client_send_command(record_p.pid, '-T func@depth=3') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-T func@clear=depth,time=3ms') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-T a@notrace') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-T a@clear -T func@clear') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        record_p.stdin.close()
        record_p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''
