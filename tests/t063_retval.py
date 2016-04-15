#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-int', result="""
# DURATION    TID     FUNCTION
   1.498 us [ 3338] | __monstartup();
   1.079 us [ 3338] | __cxa_atexit();
            [ 3338] | main() {
   3.399 us [ 3338] |   int_add(-1, 2) = 1;
   0.786 us [ 3338] |   int_sub(1, 2) = -1;
   0.446 us [ 3338] |   int_mul(3, 4) = 12;
   0.429 us [ 3338] |   int_div(4, -2) = -2;
   8.568 us [ 3338] | } /* main */
""")

    def runcmd(self):
        return '%s -A "^int_@arg1/i32,arg2/i32" -R "^int_@retval/i32" %s' \
            % (TestBase.ftrace, 't-' + self.name)
