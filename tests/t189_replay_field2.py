#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'taskname', ldflags='-pthread', result="""
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

    def pre(self):
        uftrace  = TestBase.uftrace_cmd
        argument = '-d %s -E linux:task-name' % TDIR
        program  = 't-' + self.name

        record_cmd = '%s record %s %s' % (uftrace, argument, program)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -F main -f task -d %s' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def sort(self, output, ignore_children=False):
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue;
            result.append(ln)
        return '\n'.join(result)
