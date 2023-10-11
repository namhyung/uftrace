#!/usr/bin/env python3

import os

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', serial=True, result="""
# DURATION    TID     FUNCTION
            [24464] | main() {
            [24464] |   foo() {
            [24464] |     mem_alloc() {
   4.976 us [24464] |       malloc();
  15.040 us [24464] |     } /* mem_alloc */
            [24464] |     bar() {
            [24464] |       usleep() {
            [24464] |         /* sched:sched_switch (prev_comm=t-sleep ...) */
            [24464] |         /* sched:sched_switch (prev_comm=swapper/0 ...) */
   2.176 ms [24464] |       } /* usleep */
   2.183 ms [24464] |     } /* bar */
            [24464] |     mem_free() {
  12.992 us [24464] |       free();
  15.400 us [24464] |     } /* mem_free */
   2.215 ms [24464] |   } /* foo */
   2.216 ms [24464] | } /* main */

""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option  = '-E sched:sched_switch@kernel'

    def sort(self, output, ignored=''):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        before_main = True
        for ln in output.split('\n'):
            if ln.find(' | main()') > 0:
                before_main = False
            if before_main:
                continue
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            # delete event specific info
            if ln.find('sched:sched_switch') > 0:
                ln = ' |         /* sched:sched_switch */'
            func = ln.split('|', 1)[-1]
            result.append(func)

        return '\n'.join(result)
