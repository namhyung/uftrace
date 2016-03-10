#!/usr/bin/env python

import re
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-str', result="""
# DURATION    TID     FUNCTION
            [18141] | main() {
   0.271 ms [18141] |   str_cpy("", "hello");
   0.205 ms [18141] |   str_cpy("", " world");
   0.318 ms [18141] |   str_cat("hello", " world");
   0.216 ms [18141] |   str_cpy("hello world", "goodbye");
   0.303 ms [18141] |   str_cat("goodbye", " world");
   3.134 ms [18141] | } /* main */
""")

    def runcmd(self):
        return '%s -A "^str_@arg1/s,arg2/s" %s' % (TestBase.ftrace, 't-' + self.name)
