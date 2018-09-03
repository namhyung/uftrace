#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'taskname', ldflags='-pthread', result="""
{"traceEvents":[
{"ts":0,"ph":"M","pid":4694,"name":"process_name","args":{"name":"t-taskname"}},
{"ts":0,"ph":"M","pid":4694,"name":"thread_name","args":{"name":"t-taskname"}},
{"ts":13453314717.085,"ph":"B","pid":4694,"name":"main"},
{"ts":13453314717.245,"ph":"B","pid":4694,"name":"task_name1"},
{"ts":13453314717.814,"ph":"B","pid":4694,"name":"prctl"},
{"ts":0,"ph":"M","pid":4694,"name":"process_name","args":{"name":"foo"}},
{"ts":0,"ph":"M","pid":4694,"name":"thread_name","args":{"name":"foo"}},
{"ts":13453314720.072,"ph":"E","pid":4694,"name":"prctl"},
{"ts":13453314720.665,"ph":"E","pid":4694,"name":"task_name1"},
{"ts":13453314720.793,"ph":"B","pid":4694,"name":"task_name2"},
{"ts":13453314720.920,"ph":"B","pid":4694,"name":"pthread_self"},
{"ts":13453314721.080,"ph":"E","pid":4694,"name":"pthread_self"},
{"ts":13453314721.264,"ph":"B","pid":4694,"name":"pthread_setname_np"},
{"ts":0,"ph":"M","pid":4694,"name":"process_name","args":{"name":"bar"}},
{"ts":0,"ph":"M","pid":4694,"name":"thread_name","args":{"name":"bar"}},
{"ts":13453314722.478,"ph":"E","pid":4694,"name":"pthread_setname_np"},
{"ts":13453314722.631,"ph":"E","pid":4694,"name":"task_name2"},
{"ts":13453314722.695,"ph":"E","pid":4694,"name":"main"}
], "displayTimeUnit": "ns", "metadata": {
"command_line":"../uftrace --no-pager -L.. record -d xxx t-taskname",
"recorded_time":"Tue Jan 30 16:05:24 2018"
} }
""", sort='chrome')

    def pre(self):
        uftrace  = TestBase.uftrace_cmd
        argument = '-d %s -E linux:task-name' % TDIR
        program  = 't-' + self.name

        record_cmd = '%s record %s %s' % (uftrace, argument, program)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s dump --chrome -F main -d %s' % (TestBase.uftrace_cmd.split()[0], TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
