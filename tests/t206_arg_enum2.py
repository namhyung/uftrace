#!/usr/bin/env python

from runtest import TestBase
import re

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'enum', result="""
# DURATION     TID     FUNCTION
            [ 14885] | main() {
   6.183 us [ 14885] |   kill(0, SIGNULL);
   3.120 us [ 14885] |   foo(0);
   4.095 us [ 14885] |   foo(XXX);
  17.849 us [ 14885] | } /* main */
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not "dwarf" in self.feature:
            return TestBase.TEST_SKIP
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-F main -A kill -A foo'

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
