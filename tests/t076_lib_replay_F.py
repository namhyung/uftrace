#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
# DURATION    TID     FUNCTION
            [17459] | lib_b() {
   6.911 us [17459] |   lib_c();
   8.279 us [17459] | } /* lib_b */
""", sort='simple')

    def build(self, name, cflags='', ldflags=''):
        return TestBase.build_libabc(self, name, cflags, ldflags)

    def pre(self):
        record_cmd = '%s record --force -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s -F lib_b@libabc_test' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
