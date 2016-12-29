#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
# DURATION    TID     FUNCTION
            [17460] | lib_a() {
   6.911 us [17460] |   lib_b();
   8.279 us [17460] | } /* lib_a */
""", sort='simple')

    def build(self, name, cflags='', ldflags=''):
        return TestBase.build_libabc(self, name, cflags, ldflags)

    def pre(self):
        record_cmd = '%s record --force --no-libcall -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s -T lib_a@libabc_test,depth=2' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
