#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-char', result="""
# DURATION    TID     FUNCTION
            [18279] | main() {
   0.371 ms [18279] |   foo('f', 'o', 'o');
   0.923 ms [18279] |   bar('\\x00', 'B', 97, 0x72);
   3.281 ms [18279] | } /* main */
""")

    def runcmd(self):
        return '%s -A "foo@arg1/c,arg2/c,arg3/c" -A "bar@arg1/c,arg2/c,arg3/i,arg4/x8" %s' % \
            (TestBase.ftrace, 't-' + self.name)
