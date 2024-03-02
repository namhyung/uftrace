#!/usr/bin/env python3

import os
import stat

from runtest import TestBase

TEST_SCRIPT = "./test-script.sh"

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
            [28141] | main() {
            [28141] |   a() {
            [28141] |     b() {
            [28141] |       c() {
   0.753 us [28141] |         getpid();
   1.430 us [28141] |       } /* c */
   1.915 us [28141] |     } /* b */
   2.405 us [28141] |   } /* a */
   3.005 us [28141] | } /* main */
""", sort='simple')

        f = open(TEST_SCRIPT, "w")
        f.write("""#!/bin/sh
./t-abc
""")
        f.close()
        os.chmod(TEST_SCRIPT, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

    def build(self, name, cflags='', ldflags=''):
        if cflags.find('-fpatchable-function-entry') >= 0:
            self.patchable = True
        else:
            self.patchable = False

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = "--force -F main"
        if self.patchable:
            self.option += " -P .@t-abc"

        self.exearg = TEST_SCRIPT
