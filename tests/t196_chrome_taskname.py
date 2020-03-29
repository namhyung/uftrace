#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'taskname', ldflags='-pthread', serial=True, result="""
{"traceEvents":[
{"ts":0,"ph":"M","pid":4694,"name":"process_name","args":{"name":"[4694] bar"}},
{"ts":0,"ph":"M","pid":4694,"name":"thread_name","args":{"name":"[4694] bar"}},
{"ts":13453314717.085,"ph":"B","pid":4694,"name":"main"},
{"ts":13453314717.245,"ph":"B","pid":4694,"name":"task_name1"},
{"ts":13453314717.814,"ph":"B","pid":4694,"name":"prctl"},
{"ts":0,"ph":"M","pid":4694,"name":"process_name","args":{"name":"[4694] foo"}},
{"ts":0,"ph":"M","pid":4694,"name":"thread_name","args":{"name":"[4694] foo"}},
{"ts":13453314720.072,"ph":"E","pid":4694,"name":"prctl"},
{"ts":13453314720.665,"ph":"E","pid":4694,"name":"task_name1"},
{"ts":13453314720.793,"ph":"B","pid":4694,"name":"task_name2"},
{"ts":13453314720.920,"ph":"B","pid":4694,"name":"pthread_self"},
{"ts":13453314721.080,"ph":"E","pid":4694,"name":"pthread_self"},
{"ts":13453314721.264,"ph":"B","pid":4694,"name":"pthread_setname_np"},
{"ts":0,"ph":"M","pid":4694,"name":"process_name","args":{"name":"[4694] bar"}},
{"ts":0,"ph":"M","pid":4694,"name":"thread_name","args":{"name":"[4694] bar"}},
{"ts":13453314722.478,"ph":"E","pid":4694,"name":"pthread_setname_np"},
{"ts":13453314722.631,"ph":"E","pid":4694,"name":"task_name2"},
{"ts":13453314722.695,"ph":"E","pid":4694,"name":"main"}
], "displayTimeUnit": "ns", "metadata": {
"command_line":"../uftrace record --no-pager --no-event -L.. t-taskname",
"recorded_time":"Tue Jan 30 16:05:24 2018"
} }
""", sort='chrome')

    def prerun(self, timeout):
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP

        self.subcmd = 'record'
        self.option = '-E linux:task-name'

        record_cmd = TestBase.runcmd(self)
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'dump'
        self.option = '--chrome -F main'

    def runcmd(self):
        cmd = TestBase.runcmd(self)
        return cmd.replace('--no-event', '')
