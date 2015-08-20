#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
            [20175] | alloc1() {
            [20175] |   alloc3() {
   5.792 us [20175] |     alloc5();
   7.914 us [20175] |   } /* alloc3 */
 114.958 us [20175] | } /* alloc1 */
""")

    def runcmd(self):
        return '%s -D1 -F "alloc[135]" %s' % (TestBase.ftrace, 't-allocfree')

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            func = ln.split('|', 1)[-1]
            result.append(func)

        return '\n'.join(result)
