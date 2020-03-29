#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'arg', """
# DURATION    TID     FUNCTION
            [13476] | main() {
            [13476] |   foo() {
            [13476] |     bar() {
   0.567 us [13476] |       strcmp();
   1.779 us [13476] |     } /* bar */
            [13476] |     bar() {
   0.133 us [13476] |       strcmp();
   0.489 us [13476] |     } /* bar */
            [13476] |     bar() {
   0.081 us [13476] |       strcmp();
   0.381 us [13476] |     } /* bar */
   3.515 us [13476] |   } /* foo */
   2.235 us [13476] |   many(8, 13, 21, 34, 55, 89, 144);
            [13476] |   pass() {
   0.130 us [13476] |     check();
   0.427 us [13476] |   } /* pass */
  18.161 us [13476] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option  = '-A "many@arg1/i32%stack+1,arg2/i32%stack+2" '
        self.option += '-A "many@arg3/i32%stack+3,arg4/i32%stack+4" '
        self.option += '-A "many@arg5/i32%stack5,arg6/i32%stack6,arg7/i32%stack7"'

        if TestBase.is_32bit(self):
            # i386 use stack for passing argument. so, change order.
            self.option  = '-A "many@arg1/i32%stack+7,arg2/i32%stack+8" '
            self.option += '-A "many@arg3/i32%stack+9,arg4/i32%stack+10" '
            self.option += '-A "many@arg5/i32%stack11,arg6/i32%stack12,arg7/i32%stack13"'
            # FIXME: arm has to be handled differently
