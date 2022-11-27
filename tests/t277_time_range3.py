#!/usr/bin/env python

import subprocess as sp

from runtest import TestBase

END=999999999.999999999

# when uftrace record used a time filter, it sets a default option to apply it
# to replay (mostly for schedule events).  But it clashed with a time range
# option.  This test output should not have other events like 'schedule'.
class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
#     TIMESTAMP       FUNCTION
   310743.877593890 | main() {
   310743.877593950 |   foo() {
   310743.877594592 |     bar() {
   310743.877594652 |       usleep() {

uftrace stopped tracing with remaining functions
================================================
task: 16676
[3] usleep
[2] bar
[1] foo
[0] main
""", sort='simple')

    def prerun(self, timeout):
        global END

        # record with a time filter
        self.subcmd = 'record'
        self.option = '-t 1ms'
        record_cmd = self.runcmd()
        record_cmd.replace('--no-event', '')
        sp.call(record_cmd.split())

        # find timestamp of function 'usleep'
        self.subcmd = 'replay'
        self.option = '-f time'
        replay_cmd = self.runcmd()

        p = sp.Popen(replay_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        r = p.communicate()[0].decode(errors='ignore')
        END = r.split('\n')[4].split()[0] # skip header, main, foo and bar (= 4)
        p.wait()

        TS1 = r.split('\n')[6].split()[0] # next, next line after usleep
        f = open('uftrace.data/extern.dat', 'w')
        f.write("%s %s\n" % (TS1, 'external message'))
        f.close()

        return TestBase.TEST_SUCCESS

    def setup(self):
        # replay with time range
        self.subcmd = 'replay'
        self.option = '-f time -r ~%s' % END

    def runcmd(self):
        cmd = TestBase.runcmd(self)
        return cmd.replace('--no-event', '')

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and task id
            if ln.strip() == '' or ln.startswith('task:'):
                continue
            func = ln.split('|', 1)[-1]
            result.append(func)

        return '\n'.join(result)
