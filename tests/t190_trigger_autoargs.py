#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'autoargs', result="""hello
# DURATION    TID     FUNCTION
            [16523] | main() {
   2.670 us [16523] |   strlen();
   1.336 us [16523] |   strcmp("hello", "hello") = 0;
   4.017 us [16523] |   puts();
  18.574 us [16523] | } /* main */
""")

    def setup(self):
        self.option  = '-F main -T calloc@trace-off -T strcmp@trace-on,auto-args'
        self.exearg += ' hello'
