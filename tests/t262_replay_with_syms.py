#!/usr/bin/env python3

import subprocess as sp

from runtest import TestBase

SYMDIR = "abc.syms"

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

    def prerun(self, timeout):
        # record a data with symbols
        self.subcmd = 'record'
        self.option = '-d ' + SYMDIR
        self.exearg = 't-' + self.name

        record_cmd = self.runcmd()
        sp.call(record_cmd.split())
        self.pr_debug("prerun command1: " + record_cmd)

        strip_cmd = 'strip ' + self.exearg
        sp.call(strip_cmd.split())
        self.pr_debug("prerun command2: " + strip_cmd)

        # record again with the stripped binary
        self.option = ''

        record_cmd = self.runcmd()
        sp.call(record_cmd.split())
        self.pr_debug("prerun command3: " + record_cmd)

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '--with-syms ' + SYMDIR
        self.exearg = ''
