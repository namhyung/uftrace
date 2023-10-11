#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'taskname', ldflags='-pthread', serial=True, result="""
#      TASK NAME   FUNCTION
        taskname | main() {
        taskname |   task_name1() {
        taskname |     prctl() {
             foo |       /* linux:task-name (comm="foo") */
             foo |     } /* prctl */
             foo |   } /* task_name1 */
             foo |   task_name2() {
             foo |     pthread_self();
             foo |     pthread_setname_np() {
             bar |       /* linux:task-name (comm="bar") */
             bar |     } /* pthread_setname_np */
             bar |   } /* task_name2 */
             bar | } /* main */
""", sort='simple')

    def prerun(self, timeout):
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option = '-F main -E linux:task-name -t 1'
