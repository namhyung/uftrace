#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', serial=True, result="""
# DURATION    TID     FUNCTION
            [ 6532] | /* sched:sched_process_exec (filename=t-fork pid=6532 old_pid=6532) */
            [ 6532] | main() {
            [ 6532] |   fork() {
            [ 6532] |     /* sched:sched_process_fork (comm=t-fork pid=6532 child_comm=t-fork child_pid=6536) */
 144.501 us [ 6532] |   } /* fork */
            [ 6532] |   wait() {
            [ 6532] |     /* sched:sched_process_wait (comm=t-fork pid=0 prio=120) */
            [ 6536] |   } /* fork */
            [ 6536] |   a() {
            [ 6536] |     b() {
            [ 6536] |       c() {
   1.674 us [ 6536] |         getpid();
   4.648 us [ 6536] |       } /* c */
   5.131 us [ 6536] |     } /* b */
   5.488 us [ 6536] |   } /* a */
  18.724 us [ 6536] | } /* main */
            [ 6536] | /* sched:sched_process_exit (comm=t-fork pid=6536 prio=120) */
  50.274 ms [ 6532] |   } /* wait */
            [ 6532] |   a() {
            [ 6532] |     b() {
            [ 6532] |       c() {
   3.626 us [ 6532] |         getpid();
   5.851 us [ 6532] |       } /* c */
   6.217 us [ 6532] |     } /* b */
   6.522 us [ 6532] |   } /* a */
  50.451 ms [ 6532] | } /* main */
            [ 6532] | /* sched:sched_process_exit (comm=t-fork pid=6532 prio=120) */
""")

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option  = '-E sched:sched_process_*@kernel --kernel-full --event-full'

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
            if ln.find('sched:sched_') > 0:
                ln = ln.split('(', 1)[0] + '*/'
            func = ln.split('|', 1)[-1]
            result.append(func)

        return '\n'.join(result)
