#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-mixed', result="""
# DURATION    TID     FUNCTION
            [18276] | main() {
   0.371 ms [18276] |   mixed_add(-1, 0.200000) = -0.800000;
   0.118 ms [18276] |   mixed_sub(0x400000, 2048) = 0x3ff800;
   0.711 ms [18276] |   mixed_mul(-3.000000, 80000000000) = -240000000000;
   0.923 ms [18276] |   mixed_div(4, -0.000002) = -2000000.000000;
   1.257 ms [18276] |   mixed_str("argument", 0.000000) = "return";
   4.891 ms [18276] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        argopt  = '-A "mixed_add@arg1/i32,fparg1/32"         -R "mixed_add@retval/f64" '
        argopt += '-A "mixed_sub@arg1/x,arg2"                -R "mixed_sub@retval" '
        argopt += '-A "mixed_mul@fparg1,arg1/i64"            -R "mixed_mul@retval/i64" '
        argopt += '-A "mixed_div@arg1/i64,fparg1/80%stack+1" -R "mixed_div@retval/f80" '
        argopt += '-A "mixed_str@arg1/s,fparg1"              -R "mixed_str@retval/s"'

        import platform
        if platform.machine().startswith('arm'):
            argopt = argopt.replace('fparg1/80%stack+1', 'fparg1/80')

        return '%s %s %s' % (TestBase.ftrace, argopt, 't-' + self.name)
