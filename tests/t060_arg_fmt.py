#!/usr/bin/env python

import re
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-int', result="""
# DURATION    TID     FUNCTION
            [18278] | main() {
   0.371 ms [18278] |   int_add(-1, 2);
   0.118 ms [18278] |   int_sub();
   0.711 ms [18278] |   int_mul();
   0.923 ms [18278] |   int_div(4, 0xfe);
   3.281 ms [18278] | } /* main */
""")

    def runcmd(self):
        argopt = '-A "int_add@arg1/i32,arg2/u" -A "int_div@arg1/i16,arg2/x8"'
        return '%s %s %s' % (TestBase.ftrace, argopt, 't-' + self.name)
