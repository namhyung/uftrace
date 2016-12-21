#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
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

    def pre(self):
        global START

        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())

        # find timestamp of function 'c'
        replay_cmd = '%s replay -d %s -f time -F main' % (TestBase.ftrace, TDIR)
        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode()
        START = r.split('\n')[4].split()[0] # skip header, main, a and b (= 4)
        p.wait()

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -f time -r %s~ -d %s' % (TestBase.ftrace, START, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
