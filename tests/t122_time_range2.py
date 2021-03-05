#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

START=0

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
#  ELAPSED    FUNCTION
   4.343 us |       c() {
   4.447 us |         getpid();
   5.137 us |       } /* c */
   5.436 us |     } /* b */
   5.544 us |   } /* a */
   5.626 us | } /* main */
""", sort='simple')

    def prerun(self, timeout):
        global START

        self.subcmd = 'record'
        record_cmd = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        sp.call(record_cmd.split())

        # find timestamp of function 'c'
        self.subcmd = 'replay'
        self.option = '-f elapsed -F main'
        replay_cmd = self.runcmd()
        self.pr_debug("prerun command: " + replay_cmd)

        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode(errors='ignore')
        START, unit = r.split('\n')[4].split()[0:2] # skip header, main, a and b (= 4)
        START += unit
        p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-f elapsed -r %s~' % START
