#!/usr/bin/env python

import re

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'autoargs', result="""hello
# DURATION    TID     FUNCTION
            [16523] | main() {
   2.670 us [16523] |   strlen("autoargs test") = 13;
   1.353 us [16523] |   calloc(14) = 0xADDR;
   1.150 us [16523] |   free(0xADDR);
   1.336 us [16523] |   strcmp("hello", "hello") = 0;
   4.017 us [16523] |   puts("hello") = 6;
  18.574 us [16523] | } /* main */
""")

    # override calloc() to save 2nd argument only
    def setup(self):
        self.option  = '-F main -A calloc@arg2 --auto-args'
        self.exearg += ' hello'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            # ignore uftrace message on -finstrument-functions
            if ln.startswith('uftrace:'):
                continue
            line = ln.split('|', 1)[-1]
            func = re.sub(r'0x[0-9a-f]+', '0xADDR', line)
            result.append(func)

        return '\n'.join(result)
