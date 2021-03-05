#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

# Test that task.txt files with a tid in the SESS line still work

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   a() {
            [28141] |     b() {
            [28141] |       c() {
   0.753 us [28141] |         getpid();
   1.430 us [28141] |       } /* c */
   1.915 us [28141] |     } /* b */
   2.405 us [28141] |   } /* a */
   3.005 us [28141] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        ret  = TestBase.build(self, 'abc', cflags, ldflags)
        return ret

    def prerun(self, timeout):
        self.subcmd = 'record'
        record_cmd = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        sp.call(record_cmd.split())

        # Replace pid by tid on the SESS line to test backward-compatibility
        sed_cmd = 'sed -i "/SESS/s/pid/tid/g" uftrace.data/task.txt'
        self.pr_debug("prerun command: " + sed_cmd)
        sp.call(sed_cmd, shell=True)
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
