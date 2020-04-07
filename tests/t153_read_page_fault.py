#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
            [32766] | main() {
            [32766] |   a() {
            [32766] |     b() {
            [32766] |       /* read:page-fault (major=0, minor=188) */
            [32766] |       c() {
   0.609 us [32766] |         getpid();
  13.722 us [32766] |       } /* c */
            [32766] |       /* diff:page-fault (major=+0, minor=+1) */
  24.950 us [32766] |     } /* b */
  25.564 us [32766] |   } /* a */
  26.963 us [32766] | } /* main */
""")

    def setup(self):
        self.option = '-F main -T b@read=page-fault'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            func = ln.split('|', 1)[-1]
            # remove actual numbers in page-fault
            if func.find('read:page-fault') > 0:
                func = '       /* read:page-fault */'
            if func.find('diff:page-fault') > 0:
                func = '       /* diff:page-fault */'
            result.append(func)

        return '\n'.join(result)
