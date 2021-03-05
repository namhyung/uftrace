#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'variadic', result="""
# DURATION    TID     FUNCTION
   1.334 us [ 9624] | __monstartup();
   0.869 us [ 9624] | __cxa_atexit();
            [ 9624] | main() {
            [ 9624] |   variadic("print %c %s %d %ld %lu %lld %f", 'a', "hello", 100, 1234, 5678, 9876543210, 3.141592) {
   8.979 us [ 9624] |     vsnprintf(256, "print %c %s %d %ld %lu %lld %f");
  12.642 us [ 9624] |   } /* variadic */
  13.250 us [ 9624] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option  = '-A "variadic@arg1/s,arg2/c,arg3/s,arg4,arg5,arg6,arg7/i64,fparg1" '
        self.option += '-A "vsnprintf@arg2,arg3/s" '

        if TestBase.is_32bit(self):
            self.option  = '-A "variadic@arg1/s,arg2/c,arg3/s,arg4,arg5,arg6,arg7/i64,fparg9" '
            self.option += '-A "vsnprintf@arg2,arg3/s" '
