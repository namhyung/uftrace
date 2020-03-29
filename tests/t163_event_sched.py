#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', serial=True, result="""
# DURATION    TID     FUNCTION
            [  395] | main() {
            [  395] |   foo() {
            [  395] |     bar() {
            [  395] |       usleep() {
   2.088 ms [  395] |         /* linux:schedule */
   2.105 ms [  395] |       } /* usleep */
   2.109 ms [  395] |     } /* bar */
   2.120 ms [  395] |   } /* foo */
   2.121 ms [  395] | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_dependency(self, 'perf_context_switch'):
            return TestBase.TEST_SKIP
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP
        return TestCase.TEST_SUCCESS

    def setup(self):
        self.option = '-D 2 -F main -F bar -E linux:schedule'
