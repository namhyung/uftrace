#!/usr/bin/env python

from runtest import TestBase
import re

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'autoargs', result="""
hello
# DURATION    TID     FUNCTION
            [162523] | main() {
   2.670 us [162523] |   strlen("autoargs test") = 13;
   1.353 us [162523] |   calloc(1, 14) = 0xADDR;
   1.150 us [162523] |   free(0xADDR);
   1.336 us [162523] |   strcmp("hello", "hello") = 0;
   4.017 us [162523] |   puts("hello") = 6;
  18.574 us [162523] | } /* main */
""")

    def runcmd(self):
        #return '%s -A "getenv|atoi@arg1/s" -A malloc@arg1 %s 100' %
        return '%s -F main --auto-args %s hello' % \
            (TestBase.ftrace, 't-' + self.name)

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            line = ln.split('|', 1)[-1]
            func = re.sub(r'0x[0-9a-f]+', '0xADDR', line)
            result.append(func)

        return '\n'.join(result)
