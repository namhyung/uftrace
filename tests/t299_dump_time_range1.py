#!/usr/bin/env python3

# When using 'uftrace dump --chrome --time-range', functions that were entered
# before the range start but exit within the range used to produce orphaned E
# events without matching B events, resulting in malformed traces in Perfetto.
#
# This test records the abc call chain (main -> a -> b -> c -> getpid), then
# dumps with --chrome starting the time range at c's entry.  At that point
# main, a, and b are already active, so synthetic B events must be emitted for
# them at range_start before c's natural B event.

import subprocess as sp

from runtest import TestBase

START_TIME = '0'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
{"traceEvents":[
{"ts":0,"ph":"M","pid":1,"name":"process_name","args":{"name":"[1] t-abc"}},
{"ts":0,"ph":"M","pid":1,"name":"thread_name","args":{"name":"[1] t-abc"}},
{"ts":0,"ph":"B","pid":1,"name":"main"},
{"ts":0,"ph":"B","pid":1,"name":"a"},
{"ts":0,"ph":"B","pid":1,"name":"b"},
{"ts":0,"ph":"B","pid":1,"name":"c"},
{"ts":0,"ph":"B","pid":1,"name":"getpid"},
{"ts":0,"ph":"E","pid":1,"name":"getpid"},
{"ts":0,"ph":"E","pid":1,"name":"c"},
{"ts":0,"ph":"E","pid":1,"name":"b"},
{"ts":0,"ph":"E","pid":1,"name":"a"},
{"ts":0,"ph":"E","pid":1,"name":"main"}
]}
""", sort='chrome')

    def prerun(self, timeout):
        global START_TIME

        self.subcmd = 'record'
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())

        # Find the entry timestamp of 'c' so the time range starts after
        # main, a, and b have already been entered.  Those three functions
        # must appear as synthetic B events in the chrome output.
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
        self.option = '--chrome -r %s~' % START_TIME
