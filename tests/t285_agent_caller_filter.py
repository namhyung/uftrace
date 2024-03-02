#!/usr/bin/env python3

import os.path
import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    """Add and remove caller filters at runtime from the agent.

    The target runs a loop, and starts with a caller filter on b(). We add one
    on c() so all functions appear in the trace. Then we proceed to leave only a
    caller filter on a() so it appears as a leaf in the trace.
    """

    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
            [ 30262] | main() {
            [ 30262] |   func() {
            [ 30262] |     a() {
   2.092 ms [ 30262] |       b();
   3.160 ms [ 30262] |     } /* a */
   3.160 ms [ 30262] |   } /* func */
            [ 30262] |   func() {
            [ 30262] |     a() {
            [ 30262] |       b() {
   1.075 ms [ 30262] |         c();
   2.152 ms [ 30262] |       } /* b */
   3.222 ms [ 30262] |     } /* a */
   3.223 ms [ 30262] |   } /* func */
            [ 30262] |   func() {
            [ 30262] |     a() {
            [ 30262] |       b() {
   1.063 ms [ 30262] |         c();
   2.128 ms [ 30262] |       } /* b */
   3.200 ms [ 30262] |     } /* a */
   3.200 ms [ 30262] |   } /* func */
            [ 30262] |   func() {
            [ 30262] |     a();
   3.198 ms [ 30262] |   } /* func */
  37.973 ms [ 30262] | } /* main */
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
        self.option += ' -C b'
        self.exearg = 't-' + self.name
        record_cmd  = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        # bufsize=0 to write characters one by one
        record_p = sp.Popen(record_cmd.split(), stdin=sp.PIPE, stderr=sp.PIPE, bufsize=0)

        while not os.path.exists("/tmp/uftrace/%d.socket" % record_p.pid):
            sleep(.01)

        if self.client_send_command(record_p.pid, '-C c') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-C b@clear -C a') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-C c@clear') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        record_p.stdin.close()
        record_p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''
