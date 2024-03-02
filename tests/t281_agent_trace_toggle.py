#!/usr/bin/env python3

import os.path
import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    """Run the target with the agent activated. Tracing is disabled by the
    client before triggering the second loop in the target, and restored just
    after.

    That way, func() gets executed 3 times in the target, but is only recorded 2
    times by uftrace."""
    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
            [  5650] | main() {
            [  5650] |   func() {
            [  5650] |     a() {
            [  5650] |       b() {
   0.113 us [  5650] |         c();
   1.618 us [  5650] |       } /* b */
   1.910 us [  5650] |     } /* a */
   2.301 us [  5650] |   } /* func */
            [  5650] |   func() {
            [  5650] |     a() {
            [  5650] |       b() {
   0.430 us [  5650] |         c();
   3.898 us [  5650] |       } /* b */
   4.993 us [  5650] |     } /* a */
   6.843 us [  5650] |   } /* func */
  37.310 ms [  5650] | } /* main */
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
        self.option  = '--agent'
        self.option += ' --keep-pid'
        self.option += ' --no-libcall'
        self.exearg = 't-' + self.name
        record_cmd  = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        record_p = sp.Popen(record_cmd.split(), stdin=sp.PIPE, stderr=sp.PIPE, bufsize=0)

        while not os.path.exists("/tmp/uftrace/%d.socket" % record_p.pid):
            sleep(.01)

        if self.client_send_command(record_p.pid, '--trace=off') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '--trace=on') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        record_p.stdin.close()
        record_p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''
