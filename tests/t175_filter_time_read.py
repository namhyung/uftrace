#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
# DURATION    TID     FUNCTION
            [18219] | main() {
            [18219] |   foo() {
            [18219] |     /* read:proc/statm (size=6812KB, rss=784KB, shared=716KB) */
            [18219] |     bar() {
            [18219] |       /* read:proc/statm (size=6812KB, rss=784KB, shared=716KB) */
   2.093 ms [18219] |       usleep();
   2.095 ms [18219] |     } /* bar */
   2.106 ms [18219] |   } /* foo */
   2.107 ms [18219] | } /* main */
""")

    def runcmd(self):
        uftrace = TestBase.ftrace
        args    = "-F main -t 1ms -T '(foo|bar|^mem)@read=proc/statm'"
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
