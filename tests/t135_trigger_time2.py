#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
TIME=0
UNIT=''

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
# DURATION    TID     FUNCTION
            [27437] | main() {
            [27437] |   foo() {
   2.241 us [27437] |     mem_alloc();
            [27437] |     bar() {
   2.183 ms [27437] |       usleep();
   2.185 ms [27437] |     } /* bar */
            [27437] |     mem_free() {
   3.086 us [27437] |       free();
   3.806 us [27437] |     } /* mem_free */
   2.191 ms [27437] |   } /* foo */
   2.192 ms [27437] | } /* main */
""", sort='simple')

    def prerun(self, timeout):
        global TIME, UNIT

        self.subcmd = 'record'
        self.option = '-F main'
        record_cmd = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        sp.call(record_cmd.split())

        # find timestamp of function 'malloc'
        self.subcmd = 'replay'
        self.option = '-F malloc'
        replay_cmd = self.runcmd()
        self.pr_debug("prerun command: " + replay_cmd)

        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode(errors='ignore')
        TIME, UNIT = r.split('\n')[1].split()[0:2] # skip header
        TIME = float(TIME) + 0.001 # for time filtering
        p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-T main@time=%.3f%s' % (TIME, UNIT)
