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
   2.235 us [13476] |   many(12, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144);
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

    def runcmd(self):
        argopt = '-A "many@arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12,arg13"'
        return '%s %s %s' % (TestBase.ftrace, argopt, 't-' + self.name)
