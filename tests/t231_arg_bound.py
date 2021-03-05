#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'arg', """
# DURATION     TID     FUNCTION
   0.647 us [ 17685] | __monstartup();
   0.117 us [ 17685] | __cxa_atexit();
            [ 17685] | main() {
            [ 17685] |   foo() {
            [ 17685] |     bar() {
   0.107 us [ 17685] |       strcmp();
   0.420 us [ 17685] |     } /* bar */
            [ 17685] |     bar() {
   0.044 us [ 17685] |       strcmp();
   0.181 us [ 17685] |     } /* bar */
            [ 17685] |     bar() {
   0.045 us [ 17685] |       strcmp();
   0.162 us [ 17685] |     } /* bar */
   1.122 us [ 17685] |   } /* foo */
 160.575 us [ 17685] |   many(12, 0, 1, 0);
            [ 17685] |   pass() {
   0.083 us [ 17685] |     check();
   0.303 us [ 17685] |   } /* pass */
 162.699 us [ 17685] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A "many@arg1,arg9999999,arg2,arg4294967295"'
