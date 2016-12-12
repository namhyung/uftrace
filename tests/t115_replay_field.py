#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
#     TIMESTAMP      DURATION    TID     FUNCTION
    75691.369083031            [28337] | main() {
    75691.369083271            [28337] |   a() {
    75691.369083411            [28337] |     b() {
    75691.369083545            [28337] |       c() {
    75691.369083755   0.776 us [28337] |         getpid();
    75691.369085245   1.700 us [28337] |       } /* c */
    75691.369085578   2.167 us [28337] |     } /* b */
    75691.369085788   2.517 us [28337] |   } /* a */
    75691.369085968   2.937 us [28337] | } /* main */
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -F main -f time,duration,tid -d %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
