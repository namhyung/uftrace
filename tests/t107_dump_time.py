#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
{"traceEvents":[
{"ts":0,"ph":"M","pid":32537,"name":"process_name","args":{"name":"[32537] t-sleep"}},
{"ts":0,"ph":"M","pid":32537,"name":"thread_name","args":{"name":"[32537] t-sleep"}},
{"ts":56466448731,"ph":"B","pid":32537,"name":"main"},
{"ts":56466448731,"ph":"B","pid":32537,"name":"foo"},
{"ts":56466448742,"ph":"B","pid":32537,"name":"bar"},
{"ts":56466448743,"ph":"B","pid":32537,"name":"usleep"},
{"ts":56466450823,"ph":"E","pid":32537,"name":"usleep"},
{"ts":56466450827,"ph":"E","pid":32537,"name":"bar"},
{"ts":56466450834,"ph":"E","pid":32537,"name":"foo"},
{"ts":56466450835,"ph":"E","pid":32537,"name":"main"}
], "metadata": {
"command_line":"uftrace record -d xxx t-sleep ",
"recorded_time":"Mon Oct  3 22:45:57 2016"
} }
""", sort='chrome')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'dump'
        self.option = '-t 1ms --chrome'
