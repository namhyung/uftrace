#!/usr/bin/env python3

import re

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'mmap', result="""
# DURATION    TID     FUNCTION
            [14885] | main() {
            [14885] |   foo() {
   9.397 us [14885] |     open("/dev/zero", O_RDONLY) = FD;
   3.802 us [14885] |     mmap(0, 4096, PROT_READ, MAP_ANON|MAP_PRIVATE, FD, 0) = 0xADDR;
   4.119 us [14885] |     mprotect(0xADDR, 4096, PROT_NONE) = 0;
   6.183 us [14885] |     munmap(0xADDR, 4096) = 0;
   3.120 us [14885] |     close(FD) = 0;
  36.529 us [14885] |   } /* foo */
  37.849 us [14885] | } /* main */
""")

    def setup(self):
        self.option = '-F main --auto-args'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            line = ln.split('|', 1)[-1]

            # address might be different, so replace it as 0xADDR for comparison.
            func = re.sub(r'0x[0-9a-f]+', '0xADDR', line)

            # fd number might be different, so replace it as FD for comparison.
            func = re.sub(r'O_RDONLY\) = [0-9]+', 'O_RDONLY) = FD', func)
            func = re.sub(r'MAP_PRIVATE, [0-9]+, 0', 'MAP_PRIVATE, FD, 0', func)
            func = re.sub(r'close\([0-9]+\)', 'close(FD)', func)

            result.append(func)

        return '\n'.join(result)

    def fixup(self, cflags, result):
        return result.replace('5', '4')
