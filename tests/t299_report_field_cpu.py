#!/usr/bin/env python3

import os
import subprocess as sp

from runtest import TestBase


class TestCase(TestBase):
    def __init__(self):
        ncpus = os.cpu_count()

        expected_lines = [
            "CPU      Function",
            "==========  ====================",
            "0  task_a",
            "1  task_b"
        ]

        if ncpus > 2:
            expected_lines.append("2  task_c")
        if ncpus > 3:
            expected_lines.append("3  task_d")

        TestBase.__init__(self, 'per-cpu', result='\n'.join(expected_lines))

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
        self.option = '-f cpu'

    def runcmd(self):
        cmd = TestBase.runcmd(self)
        return cmd.replace('--no-event', '')

    def sort(self, output):
        header = []
        body = []

        ncpus = os.cpu_count()
        target_funcs = {'task_a', 'task_b'}
        if ncpus > 2:
            target_funcs.add('task_c')
        if ncpus > 3:
            target_funcs.add('task_d')

        for ln in output.split('\n'):
            if not ln.strip():
                continue
            line = ln.split()
            if not line:
                continue

            if line[0] == 'CPU' and line[1] == 'Function':
                header.append('CPU      Function')
                continue
            if line[0].startswith('='):
                header.append('==========  ====================')
                continue

            cpu = line[0]
            func = ' '.join(line[1:])

            if func in target_funcs:
                body.append('%s  %s' % (cpu, func))

        body.sort()

        return '\n'.join(header + body)
