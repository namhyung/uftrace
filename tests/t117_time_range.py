#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

START=0

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
#     TIMESTAMP       FUNCTION
    74469.340765344 |       c() {
    74469.340765524 |         getpid();
    74469.340766935 |       } /* c */
    74469.340767195 |     } /* b */
    74469.340767372 |   } /* a */
    74469.340767541 | } /* main */
""", sort='simple')

    def prerun(self, timeout):
        global START

        self.subcmd = 'record'
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())

        # find timestamp of function 'c'
        self.subcmd = 'replay'
        self.option = '-f time -F main'
        replay_cmd = self.runcmd()

        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode(errors='ignore')
        START = r.split('\n')[4].split()[0] # skip header, main, a and b (= 4)
        p.wait()

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-f time -r %s~' % START
