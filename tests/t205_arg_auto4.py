#!/usr/bin/env python

from runtest import TestBase
import re

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'autoargs', result="""autoargs test
# DURATION     TID     FUNCTION
            [ 16523] | main(2, 0xADDR) {
   2.670 us [ 16523] |   strlen("autoargs test") = 13;
   1.353 us [ 16523] |   calloc(1, 14) = 0xADDR;
   1.150 us [ 16523] |   free(0xADDR);
   1.336 us [ 16523] |   strcmp("hello", "bye") = 6;
   4.017 us [ 16523] |   puts("autoargs test") = 14;
  18.574 us [ 16523] | } = 0; /* main */
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option  = '-F main --auto-args'
        self.exearg += ' bye'

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
