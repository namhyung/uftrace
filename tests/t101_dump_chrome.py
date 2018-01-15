#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
{"traceEvents":[
{"ts":58348873444,"ph":"B","pid":5231,"name":"main"},
{"ts":58348873444,"ph":"B","pid":5231,"name":"a"},
{"ts":58348873445,"ph":"B","pid":5231,"name":"b"},
{"ts":58348873445,"ph":"B","pid":5231,"name":"c"},
{"ts":58348873448,"ph":"E","pid":5231,"name":"c"},
{"ts":58348873448,"ph":"E","pid":5231,"name":"b"},
{"ts":58348873448,"ph":"E","pid":5231,"name":"a"},
{"ts":58348873449,"ph":"E","pid":5231,"name":"main"}
], "metadata": {
"command_line":"uftrace record -d abc.data t-abc ",
"recorded_time":"Sat Oct  1 18:19:06 2016"
} }
""", sort='chrome')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s dump -d %s -F main -D 4 --chrome' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
