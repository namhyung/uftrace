#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'taskname', ldflags='-pthread', serial=True, result="""
#      TASK NAME   FUNCTION
      t-taskname | main() {
      t-taskname |   task_name1() {
      t-taskname |     prctl() {
             foo |     } /* prctl */
             foo |   } /* task_name1 */
             foo |   task_name2() {
             foo |     pthread_self();
             foo |     pthread_setname_np() {
             bar |     } /* pthread_setname_np */
             bar |   } /* task_name2 */
             bar | } /* main */
""")

    def prerun(self, timeout):
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP

        self.subcmd = 'record'
        self.option = '-E linux:task-name'

        record_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-F main -f task'

    def sort(self, output, ignore_children=False):
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue;
            result.append(ln)
        return '\n'.join(result)
