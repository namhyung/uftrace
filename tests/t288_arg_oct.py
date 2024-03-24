#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'arg-oct', result="""
# DURATION     TID     FUNCTION
            [1587104] | main() {
 120.272 us [1587104] |   creat("bar.foo", 0755);
   3.210 us [1587104] |   chmod("bar.foo", 0777);
   6.350 us [1587104] |   unlink("bar.foo");
 131.752 us [1587104] | } /* main */
""")

    def setup(self):
        self.option = '-F main -A creat -A chmod -A unlink'
