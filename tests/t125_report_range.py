#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
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

    def pre(self):
        global START

        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())

        # find timestamp of function 'c'
        replay_cmd = '%s replay -d %s -f time -F main' % (TestBase.ftrace, TDIR)
        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode()
        START = r.split('\n')[6].split()[0] # skip header, main, a, b, c and getpid (= 6)
        p.wait()

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report -F main -r ~%s -d %s' % (TestBase.ftrace, START, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
