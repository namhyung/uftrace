#!/usr/bin/env python3

import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
  34.330 ms [ 22621] | main();
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

        sleep(.05)              # time for the agent to start
        if self.client_send_command(record_p.pid, '') != 0:
            return TestBase.TEST_NONZERO_RETURN
        record_p.stdin.write(b'0')

        record_p.stdin.close()
        record_p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-D 1'
        self.exearg = ''
