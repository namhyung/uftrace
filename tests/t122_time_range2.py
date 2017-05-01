#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
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

    def pre(self):
        global START

        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())

        # find timestamp of function 'c'
        replay_cmd = '%s replay -d %s -f elapsed -F main' % (TestBase.ftrace, TDIR)
        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode(errors='ignore')
        START, unit = r.split('\n')[4].split()[0:2] # skip header, main, a and b (= 4)
        START += unit
        p.wait()

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -f elapsed -r %s~ -d %s' % (TestBase.ftrace, START, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
