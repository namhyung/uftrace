#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'malloc', """
# DURATION    TID     FUNCTION
            [16726] | main() {
   0.426 us [16726] |   malloc();
   0.397 us [16726] |   free();
   3.074 us [16726] | } /* main */
   0.562 us [16726] | free();
""")

    def fixup(self, cflags, result):
        return result.replace('| free();', '| free();\n [16726] | free();')
