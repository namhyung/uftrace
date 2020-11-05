#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dwarf3', """
# DURATION     TID     FUNCTION
            [ 28332] | main() {
            [ 28332] |   C::C(0x7ffce3e4fe30, 1, "debug info") {
   0.686 us [ 28332] |     C::construct(0x7ffce3e4fe30, 1, "debug info");
 449.541 us [ 28332] |   } /* C::C */
            [ 28332] |   C::C(0x7ffce3e4fe40, 2, "<0x1234>") {
   0.340 us [ 28332] |     C::construct(0x7ffce3e4fe40, 2, "<0x1234>");
   1.296 us [ 28332] |   } /* C::C */
            [ 28332] |   C::C(0x7ffce3e4fe60, 0x7ffce3e4fe30) {
   0.432 us [ 28332] |     C::copy(0x7ffce3e4fe60, 1, "debug info");
   1.360 us [ 28332] |   } /* C::C */
            [ 28332] |   foo(C{...}, 0x7ffce3e4fe40, "passed by value", 0.001000) {
            [ 28332] |     C::C(0x7ffce3e4fe50, 3, "passed by value") {
   0.346 us [ 28332] |       C::construct(0x7ffce3e4fe50, 3, "passed by value");
   1.332 us [ 28332] |     } /* C::C */
   2.225 us [ 28332] |   } = C{...}; /* foo */
 457.250 us [ 28332] | } = 0; /* main */
""", lang='C++', cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A . -R . -F main'

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
