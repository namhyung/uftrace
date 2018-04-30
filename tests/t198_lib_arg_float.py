#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'float-libcall', result="""
# DURATION    TID     FUNCTION
            [18276] | main() {
   0.371 ms [18276] |   expf(1.000000) = 2.718282;
   0.118 ms [18276] |   log(2.718282) = 1.000000;
   3.281 ms [18276] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        ldflags += " -lm"
        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        argopt  = '-A "expf@fparg1/32" -R "expf@retval/f32" '
        argopt += '-A "log@fparg1/64"  -R "log@retval/f64" '

        return '%s %s %s' % (TestBase.uftrace_cmd, argopt, 't-' + self.name)
