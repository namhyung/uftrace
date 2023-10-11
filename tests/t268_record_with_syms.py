#!/usr/bin/env python3

import subprocess as sp

from runtest import TestBase

SYMDIR = "abc.syms"

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 28143] | a() {
            [ 28143] |   b() {
            [ 28143] |     c() {
   0.753 us [ 28143] |       getpid();
   1.430 us [ 28143] |     } /* c */
   1.915 us [ 28143] |   } /* b */
   2.167 us [ 28143] | } /* a */
""", sort='simple')

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

        # record again with the stripped binary + with-syms
        self.option = '-F a --with-syms ' + SYMDIR

        record_cmd = self.runcmd()
        sp.call(record_cmd.split())
        self.pr_debug("prerun command3: " + record_cmd)

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''
