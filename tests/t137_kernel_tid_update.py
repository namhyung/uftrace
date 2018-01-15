#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork2', """
# DURATION    TID     FUNCTION
            [19227] | main() {
 328.451 us [19227] |   fork();
            [19227] |   wait() {
            [19231] |   } /* fork */
            [19231] |   open() {
  17.068 us [19231] |     sys_open();
  21.964 us [19231] |   } /* open */
            [19231] |   close() {
   2.537 us [19231] |     sys_close();
   7.057 us [19231] |   } /* close */
            [19231] | } /* main */
  40.601 ms [19227] |   } /* wait */
            [19227] |   open() {
  30.832 us [19227] |     sys_open();
  37.121 us [19227] |   } /* open */
            [19227] |   close() {
   2.950 us [19227] |     sys_close();
   9.520 us [19227] |   } /* close */
  41.010 ms [19227] | } /* main */
""")

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        filters = '-F main -F sys_open@kernel -F sys_close@kernel'
        return '%s -k %s %s' % (uftrace, filters, 't-' + self.name)
