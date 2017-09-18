#!/usr/bin/env python

from runtest import TestBase
import re

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'autoargs', result="""hello
# DURATION    TID     FUNCTION
            [16523] | main() {
   2.670 us [16523] |   strlen("autoargs test") = 13;
   1.353 us [16523] |   calloc();
   1.150 us [16523] |   free();
   1.336 us [16523] |   strcmp("hello", "hello") = 0;
   4.017 us [16523] |   puts();
  18.574 us [16523] | } /* main */
""")

    def runcmd(self):
        return '%s -F main -A ^str -R ^str %s hello' % (TestBase.ftrace, 't-' + self.name)
