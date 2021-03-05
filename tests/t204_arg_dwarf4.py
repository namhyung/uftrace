#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exception4', """
# DURATION     TID     FUNCTION
            [ 15296] | main() {
            [ 15296] |   foo(1) {
   2.490 us [ 15296] |     __cxa_allocate_exception();
  47.390 us [ 15296] |   } /* foo */
  51.560 us [ 15296] | } = 0; /* main */
""", lang='C++', cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A . -R . -F main -N personality_v.'

    def sort(self, output):
        import re

        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            line = ln.split('|', 1)[-1]
            func = re.sub(r'0x[0-9a-f]+', '0xADDR', line)
            result.append(func)

        return '\n'.join(result)
