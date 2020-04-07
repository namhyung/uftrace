#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread-name', """
# DURATION     TID     FUNCTION
            [256519] | thread_first() {
            [256519] |   foo() {
            [256519] |     /* read:pmu-cycle (cycle=752, instructions=50) */
            [256519] |     /* diff:pmu-cycle (cycle=+8074, instructions=+3581, IPC=0.44) */
  84.405 us [256519] |   } /* foo */
   0.467 us [256519] |   bar();
 110.107 us [256519] | } /* thread_first */
            [256520] | thread_second() {
            [256520] |   foo() {
            [256520] |     /* read:pmu-cycle (cycle=862, instructions=50) */
            [256520] |     /* diff:pmu-cycle (cycle=+7697, instructions=+3581, IPC=0.47) */
  63.753 us [256520] |   } /* foo */
   0.385 us [256520] |   bar();
  90.445 us [256520] | } /* thread_second */
            [256521] | thread_third() {
            [256521] |   foo() {
            [256521] |     /* read:pmu-cycle (cycle=853, instructions=50) */
            [256521] |     /* diff:pmu-cycle (cycle=+8113, instructions=+3581, IPC=0.44) */
  74.033 us [256521] |   } /* foo */
   0.600 us [256521] |   bar();
 131.233 us [256521] | } /* thread_third */
            [256522] | thread_fourth() {
            [256522] |   foo() {
            [256522] |     /* read:pmu-cycle (cycle=511, instructions=50) */
            [256522] |     /* diff:pmu-cycle (cycle=+7308, instructions=+3581, IPC=0.49) */
  39.475 us [256522] |   } /* foo */
   0.209 us [256522] |   bar();
  55.132 us [256522] | } /* thread_fourth */
""", ldflags='-pthread')

    def prerun(self, timeout):
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP
        return TestCase.TEST_SUCCESS

    def setup(self):
        self.option = '-T foo@read=pmu-cycle'

    def sort(self, output):
        import re
        pid_patt = re.compile('[^[]+\[ *(\d+)\] |')
        pid_list = {}
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            m = pid_patt.match(ln)
            try:
                pid = int(m.group(1))
            except:
                continue

            func = ln.split('|', 1)[-1]
            # remove actual numbers in pmu-cycle
            if func.find('read:pmu-cycle') > 0:
                func = '     /* read:pmu-cycle */'
            if func.find('diff:pmu-cycle') > 0:
                func = '     /* diff:pmu-cycle */'

            if pid not in pid_list:
                pid_list[pid] = []
            pid_list[pid].append(func)

        result = ''
        for n in ['first', 'second', 'third', 'fourth']:
            for pid in pid_list:
                if pid_list[pid][0].find('thread_'+n) > 0:
                    result += '\n'.join(pid_list[pid]) + '\n'
        return result
