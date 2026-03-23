#!/usr/bin/env python3

# When using 'uftrace dump --time-range', raw dump (do_dump_file) simply
# filters out records outside the range without emitting synthetic entry
# events.  Functions entered before range_start (main, a, b) will have
# their exit records present but no matching entry records.
#
# This test records the abc call chain (main -> a -> b -> c -> getpid),
# then dumps with --time-range starting at c's entry.  The raw dump output
# must start from c's entry and include the orphaned exits for b, a, main.

import re
import subprocess as sp

from runtest import TestBase

START_TIME = '0'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
[entry] c depth: 3
[entry] getpid depth: 4
[exit ] getpid depth: 4
[exit ] c depth: 3
[exit ] b depth: 2
[exit ] a depth: 1
[exit ] main depth: 0
""")

    def prerun(self, timeout):
        global START_TIME

        self.subcmd = 'record'
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())

        # Find the entry timestamp of 'c' so the time range starts after
        # main, a, and b have already been entered.
        self.subcmd = 'replay'
        self.option = '-f time -F main'
        replay_cmd = self.runcmd()

        with sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE) as p:
            r = p.communicate()[0].decode(errors='ignore')
        lines = r.split('\n')
        if len(lines) < 5:
            return TestBase.TEST_DIFF_RESULT
        START_TIME = lines[4].split()[0]  # skip header, main, a, b (= 4 lines)

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'dump'
        self.option = '-r %s~' % START_TIME

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            m = re.search(r'(\[(?:entry|exit )\]) (\w+)\S* depth: (\d+)', ln)
            if m:
                result.append('%s %s depth: %s' % (m.group(1), m.group(2), m.group(3)))
        return '\n'.join(result)
