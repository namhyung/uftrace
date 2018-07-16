#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exception', """
# DURATION     TID     FUNCTION
            [ 16852] | main() {
   0.363 us [ 16852] |   foo();
            [ 16852] |   test() {
            [ 16852] |     oops() {
   2.010 us [ 16852] |       __cxa_allocate_exception();
   1.536 us [ 16852] |       std::exception::exception(0x5563ebb0c540);
  32.955 us [ 16852] |     } /* oops */
  35.498 us [ 16852] |   } /* test */
   0.183 us [ 16852] |   bar();
  39.911 us [ 16852] | } = 0; /* main */
""", lang='C++', cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        return '%s %s %s' % (TestBase.uftrace_cmd,
                             '-A . -R . -F main -N personality_v.',
                             't-' + self.name)

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
