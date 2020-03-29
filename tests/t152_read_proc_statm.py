#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
            [32417] | main() {
            [32417] |   a() {
            [32417] |     b() {
            [32417] |       /* read:proc/statm (size=6812KB, rss=780KB, shared=716KB) */
            [32417] |       c() {
   0.479 us [32417] |         getpid();
   3.014 us [32417] |       } /* c */
            [32417] |       /* diff:proc/statm (size=+0KB, rss=+0KB, shared=+0KB) */
  16.914 us [32417] |     } /* b */
  17.083 us [32417] |   } /* a */
  17.873 us [32417] | } /* main */
""")

    def setup(self):
        self.option = '-F main -T b@read=proc/statm'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            func = ln.split('|', 1)[-1]
            # remove actual numbers in proc.statm
            if func.find('read:proc/statm') > 0:
                func = '       /* read:proc/statm */'
            if func.find('diff:proc/statm') > 0:
                func = '       /* diff:proc/statm */'
            result.append(func)

        return '\n'.join(result)
