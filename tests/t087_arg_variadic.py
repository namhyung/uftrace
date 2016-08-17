#!/usr/bin/env python

import re
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'variadic', result="""
# DURATION    TID     FUNCTION
   1.334 us [ 9624] | __monstartup();
   0.869 us [ 9624] | __cxa_atexit();
            [ 9624] | main() {
            [ 9624] |   variadic("print %c %s %d %ld %lu %lld %f", 'a', "hello", 100, 1234, 5678, 9876543210, 3.141592) {
   8.979 us [ 9624] |     vsnprintf(256, "print %c %s %d %ld %lu %lld %f");
  12.642 us [ 9624] |   } /* variadic */
  13.250 us [ 9624] | } /* main */
""")

    def runcmd(self):
        argopt  = '-A "variadic@arg1/s,arg2/c,arg3/s,arg4,arg5,arg6,arg7/i64,fparg1" '
        argopt += '-A "vsnprintf@arg2,arg3/s"'

        return '%s %s %s' % (TestBase.ftrace, argopt, 't-' + self.name)
