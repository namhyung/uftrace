#!/usr/bin/env python

import re
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-int', result="""
# DURATION    TID     FUNCTION
            [18279] | main() {
   0.371 ms [18279] |   int_add(-1, 2);
   0.118 ms [18279] |   int_sub(1, 2);
   0.711 ms [18279] |   int_mul(3, 0x4);
   0.923 ms [18279] |   int_div(4, -2);
   3.281 ms [18279] | } /* main */
""")

    def runcmd(self):
        return '%s -A "int_mul@arg2/x" -A "^int_@arg1,arg2" -A "int_add@arg1/i32" %s' % \
            (TestBase.ftrace, 't-' + self.name)
