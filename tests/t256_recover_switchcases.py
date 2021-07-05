#!/usr/bin/env python

import os
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'switchcases', """
# DURATION     TID     FUNCTION
            [1084631] | main() {
            [1084631] |   call1() {
   4.498 us [1084631] |     printf();
   6.181 us [1084631] |   } /* call1 */
   2.434 us [1084631] |   printf();
   1.974 us [1084631] |   printf();
   2.114 us [1084631] |   printf();
   0.932 us [1084631] |   printf();
   1.954 us [1084631] |   printf();
   1.042 us [1084631] |   printf();
   2.094 us [1084631] |   printf();
  21.501 us [1084631] | } /* main */

""", sort='custom')

    def custom_sort(self, output, ignored):
        jump_expected = set()
        jump_found = set()

        for line in output.split('\n'):
            if line.startswith('target jump location'):
                jump_found.add(int(line.split(' ')[-1]))
            elif line.startswith('jump location'):
                jump_expected.add(int(line.split(' ')[-1], 10))

        if len(jump_expected) != len(jump_found):
            return 'invalid jumps found\n\texpected={}\n\tfound={}'.format(jump_expected, jump_found)

        jump_invalid = set()
        for found in jump_found:
            if found in jump_expected or found+4 in jump_expected:
                continue
            jump_invalid.add(found)
            
        if len(jump_invalid) != 0:
            return 'invalid jumps found\n\texpected={}\n\tinvalids={}'.format(jump_expected, jump_invalid)

        return self.task_sort(output, ignored)

    def build(self, name, cflags='', ldflags=''):
        cflags = cflags.replace('-pg', '')
        cflags = cflags.replace('-finstrument-functions', '')
        cflags += ' -fno-inline'
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        os.environ['LIBRESOLVER_PRINT_TARGETS'] = ''
        self.option = '-P.'
