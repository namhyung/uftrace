#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

START=0

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
    2.160 us    0.172 us           1  main
    1.988 us    0.126 us           1  a
    1.862 us    0.375 us           1  b
    1.487 us    0.747 us           1  c
    0.740 us    0.740 us           1  getpid
""", sort='report')

    def prerun(self, timeout):
        global START

        self.subcmd = 'record'
        record_cmd = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        sp.call(record_cmd.split())

        # find timestamp of function 'c'
        self.subcmd = 'replay'
        self.option = '-f time -F main'
        replay_cmd = self.runcmd()
        self.pr_debug("prerun command: " + replay_cmd)

        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode(errors='ignore')
        START = r.split('\n')[6].split()[0] # skip header, main, a, b, c and getpid (= 6)
        p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'report'
        self.option = '-F main -r ~%s' % START
