#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
# DURATION    TID     FUNCTION
            [17456] | lib_b() {
   6.911 us [17456] |   lib_c();
   8.279 us [17456] | } /* lib_b */
""", sort='simple')

    def build(self, name, cflags='', ldflags=''):
        return TestBase.build_libabc(self, name, cflags, ldflags)

    def runcmd(self):
        return '%s --force -F lib_b@libabc_test %s' % (TestBase.ftrace, 't-' + self.name)
