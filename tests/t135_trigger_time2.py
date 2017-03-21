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

    def pre(self):
        global TIME, UNIT

        record_cmd = '%s record -F main -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())

        # find timestamp of function 'malloc'
        replay_cmd = '%s replay -d %s -F malloc' % (TestBase.ftrace, TDIR)
        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode()
        TIME, UNIT = r.split('\n')[1].split()[0:2] # skip header
        TIME = float(TIME) + 0.001 # for time filtering
        p.wait()

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -T main@time=%.3f%s -d %s' % (TestBase.ftrace, TIME, UNIT, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
