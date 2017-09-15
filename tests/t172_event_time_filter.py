#!/usr/bin/env python

import re
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'time-to-sleep', result="""
# DURATION    TID     FUNCTION
            [48790] | main() {
            [48790] |   foo() {
            [48790] |     bar() {
            [48790] |       /* read:proc/statm (size=27368KB, rss=3192KB, shared=2928KB) */
   2.093 ms [48790] |       usleep();
   2.124 ms [48790] |     } /* bar */
   2.130 ms [48790] |   } /* foo */
   3.257 ms [48790] | } /* main */
""")

    def runcmd(self):
        uftrace = TestBase.ftrace
        args    = '-F main -t 2ms -T bar@read=proc/statm'
        prog    = 't-' + self.name
        return '%s %s %s' % (uftrace, args, prog)

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
            result.append(func)

        return '\n'.join(result)
