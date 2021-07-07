#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'uftrace_print', """
# DURATION     TID     FUNCTION
            [129490] | pass(3) {
 319.995 us [129490] |   uftrace_print("&b", 0xADDR);
            [129490] |   check(0xADDR, 0xADDR) {
   0.470 us [129490] |     uftrace_print("val.c", 'b');
   0.453 us [129490] |     uftrace_print("ref->d", 3.140000);
   0.403 us [129490] |     uftrace_print("val.s", -1);
   0.333 us [129490] |     uftrace_print("ref->ld", 0xADDR);
   0.270 us [129490] |     uftrace_print("val.i", 3);
   0.326 us [129490] |     uftrace_print("ref->ull", 0xADDR);
   0.274 us [129490] |     uftrace_print("val.l", 12345);
   0.474 us [129490] |     uftrace_print(""string test!"", "string test!");
   0.350 us [129490] |     uftrace_print("val.str", "hello");
   0.330 us [129490] |     uftrace_print("ref->str", "hello");
   7.260 us [129490] |   } = 0; /* check */
 331.649 us [129490] | } = 0; /* pass */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, '%s -g -I%s/include' % (cflags, TestBase.basedir), ldflags)

    def runcmd(self):
        return '%s --auto-args -F pass %s' % (TestBase.uftrace_cmd, 't-' + self.name)

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
