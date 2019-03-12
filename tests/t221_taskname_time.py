#!/usr/bin/env python

from runtest import TestBase

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'taskname', ldflags='-pthread', serial=True, result="""
#      TASK NAME   FUNCTION
        taskname | main() {
        taskname |   task_name1() {
        taskname |     prctl() {
             foo |       /* linux:task-name (name=foo) */
             foo |     } /* prctl */
             foo |   } /* task_name1 */
             foo |   task_name2() {
             foo |     pthread_self();
             foo |     pthread_setname_np() {
             bar |       /* linux:task-name (name=bar) */
             bar |     } /* pthread_setname_np */
             bar |   } /* task_name2 */
             bar | } /* main */
""", sort='simple')

    def runcmd(self):
        uftrace  = TestBase.uftrace_cmd
        options = '-F main -E linux:task-name -t 1'
        program  = 't-' + self.name

        return '%s %s %s' % (uftrace, options, program)
