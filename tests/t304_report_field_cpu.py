#!/usr/bin/env python3

import os
import subprocess as sp

from runtest import TestBase


class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'per-cpu', result="""\
  CPU LIST  Function
  ========  ====================
     0      func_cpu0
     1      func_cpu1""")

    def prerun(self, timeout):
        if not TestBase.check_dependency(self, 'perf_context_switch'):
            return TestBase.TEST_SKIP
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP

        if os.cpu_count() < 2:
            return TestBase.TEST_SKIP

        self.subcmd = 'record'
        self.option = ''
        record_cmd = TestBase.runcmd(self)
        record_cmd = record_cmd.replace('--no-event', '')
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'report'
        self.option = '-f cpu-list -F ^func_cpu@depth=1 -s func'

    def runcmd(self):
        cmd = TestBase.runcmd(self)
        return cmd.replace('--no-event', '')

    def sort(self, output):
        """ Each func_cpuN row should have CPU N in its cpu-list.  The list
            may also contain other CPUs the function ran on briefly, so this
            normalizes to assert containment rather than exact equality. """
        result = []
        for ln in output.split('\n'):
            line = ln.split()
            if not line or line[0] == 'CPU' or line[0].startswith('='):
                continue
            if len(line) >= 2 and line[1].startswith('func_cpu'):
                target = line[1][len('func_cpu'):]
                cpus = line[0].split('/')
                cpu_norm = target if target in cpus else line[0]
                result.append('%s %s' % (cpu_norm, line[1]))
        return '\n'.join(result)
