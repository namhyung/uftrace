#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', """
# DURATION    TID     FUNCTION
   0.636 us [  403] | __monstartup();
   0.623 us [  403] | __cxa_atexit();
            [  403] | open() {
   4.433 us [  403] |   sys_open();
   6.000 us [  403] | } /* open */
            [  403] | close() {
   0.282 us [  403] |   sys_close();
   1.731 us [  403] | } /* close */
""", sort='simple')

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        return TestBase.build(self, name, '-pg -mfentry -mnop-mcount', ldflags)

    def runcmd(self):
        return '%s -k -P %s %s openclose' % \
            (TestBase.ftrace, 'sys_*@kernel', 't-' + self.name)
