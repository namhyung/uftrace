#!/usr/bin/env python

from runtest import TestBase
import re

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'mmap', result="""
# DURATION    TID     FUNCTION
            [14885] | main() {
            [14885] |   foo() {
   9.397 us [14885] |     open("/dev/zero", O_RDONLY) = 3;
   3.802 us [14885] |     mmap(0, 4096, PROT_READ, MAP_ANON|MAP_PRIVATE, 3, 0) = 0xADDR;
   4.119 us [14885] |     mprotect(0xADDR, 4096, PROT_NONE) = 0;
   6.183 us [14885] |     munmap(0xADDR, 4096) = 0;
   3.120 us [14885] |     close(3) = 0;
  36.529 us [14885] |   } /* foo */
  37.849 us [14885] | } /* main */
""")

    def runcmd(self):
        return '%s -F main --auto-args %s' % (TestBase.uftrace_cmd, 't-' + self.name)

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            line = ln.split('|', 1)[-1]
            func = re.sub(r'0x[0-9a-f]+', '0xADDR', line)
            result.append(func)

        return '\n'.join(result)
