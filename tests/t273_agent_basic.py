#!/usr/bin/env python

import subprocess as sp
from time import sleep

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'agent', """
# DURATION     TID     FUNCTION
            [ 22621] | main() {
  43.742 ms [ 22621] |   getchar();
  43.759 ms [ 22621] | } /* main */
""")

    def prerun(self, timeout):
        self.subcmd = 'record'
        self.option = '--keep-pid -g'
        self.exearg = 't-' + self.name
        record_cmd  = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        record_p = sp.Popen(record_cmd.split(), stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)

        sleep(.05)              # time for the agent to start
        self.subcmd = 'live'
        self.option = '-p %d' % record_p.pid
        self.exearg = ''
        client_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + client_cmd)
        client_ret = sp.call(client_cmd.split())

        record_p.communicate(b"^D") # target waits for a char to end
        record_p.wait()

        if client_ret != 0:
            return TestBase.TEST_NONZERO_RETURN
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''
