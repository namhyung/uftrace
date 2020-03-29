#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
{"traceEvents":[
{"ts":0,"ph":"M","pid":5231,"name":"process_name","args":{"name":"[5231] t-abc"}},
{"ts":0,"ph":"M","pid":5231,"name":"thread_name","args":{"name":"[5231] t-abc"}},
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

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'dump'
        self.option = '-F main -D 4 --chrome'
