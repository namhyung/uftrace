#!/usr/bin/env python

import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
            [ 21279] | main() {
            [ 21279] |   func() {
            [ 21279] |     a() {
            [ 21279] |       b() {
   1.057 ms [ 21279] |         c();
   2.118 ms [ 21279] |       } /* b */
   3.169 ms [ 21279] |     } /* a */
   3.170 ms [ 21279] |   } /* func */
            [ 21279] |   func(3, "test") {
            [ 21279] |     a() {
            [ 21279] |       b() {
   1.058 ms [ 21279] |         c(0) = 0xcafe;
   2.121 ms [ 21279] |       } /* b */
   3.182 ms [ 21279] |     } /* a */
   3.336 ms [ 21279] |   } /* func */
            [ 21279] |   func(3, "test") {
            [ 21279] |     a(2) {
            [ 21279] |       b(1) {
   1.058 ms [ 21279] |         c(0) = 0xcafe;
   2.122 ms [ 21279] |       } = 51967; /* b */
   3.187 ms [ 21279] |     } = 51968; /* a */
   3.191 ms [ 21279] |   } = 51969; /* func */
  65.515 ms [ 21279] | } /* main */
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

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
        self.exearg = f't-{self.name} test'
        record_cmd  = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        # bufsize=0 to write characters one by one
        record_p = sp.Popen(record_cmd.split(), stdin=sp.PIPE, stderr=sp.PIPE, bufsize=0)

        sleep(.05)              # time for the agent to start

        if self.client_send_command(record_p.pid, '-A c@arg1 -R c@retval/x') != 0:
            return TestBase.TEST_NONZERO_RETURN
        if self.client_send_command(record_p.pid, '-A func@arg1,arg2/s') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        if self.client_send_command(record_p.pid, '-a') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        record_p.stdin.close()
        record_p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''
