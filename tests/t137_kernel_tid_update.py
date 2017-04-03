#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'forkexec', """
# DURATION    TID     FUNCTION
            [ 9874] | main() {
 142.145 us [ 9874] |   fork();
            [ 9874] |   waitpid() {
 473.298 us [ 9875] |   } /* fork */
            [ 9875] |   execl() {
            [ 9875] | main() {
            [ 9875] |   open() {
  14.416 us [ 9875] |     sys_open();
  19.099 us [ 9875] |   } /* open */
            [ 9875] |   close() {
   3.380 us [ 9875] |     sys_close();
   9.720 us [ 9875] |   } /* close */
  37.051 us [ 9875] | } /* main */
   2.515 ms [ 9874] |   } /* waitpid */
   2.708 ms [ 9874] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        ret  = TestBase.build(self, 'openclose', cflags, ldflags)
        ret += TestBase.build(self, self.name, cflags, ldflags)
        return ret

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s -k -F %s -F %s -F %s %s openclose' % \
            (TestBase.ftrace, 'main', 'sys_open@kernel', 'sys_close@kernel', 't-' + self.name)
