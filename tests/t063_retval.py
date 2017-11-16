#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-int', result="""
# DURATION    TID     FUNCTION
   1.498 us [ 3338] | __monstartup();
   1.079 us [ 3338] | __cxa_atexit();
            [ 3338] | main() {
   3.399 us [ 3338] |   int_add(-1, 2) = 1;
   0.786 us [ 3338] |   int_sub(1, 2) = -1;
   0.446 us [ 3338] |   int_mul(3, 4) = 12;
   0.429 us [ 3338] |   int_div(4, -2) = -2;
   8.568 us [ 3338] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support return value now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        argopt = '-A "^int_@arg1,arg2" -R "^int_@retval/i32"'

        import platform
        if platform.architecture()[0].startswith('32bit'):
            # int_mul@arg1 is a 'long long', so we should skip arg2
            argopt  = '-A "int_(add|sub|div)@arg1,arg2" -A "int_mul@arg1/i64,arg3" '
            argopt += '-R "^int_@retval/i32"'
      
        return '%s %s %s' % (TestBase.ftrace, argopt, 't-' + self.name)
