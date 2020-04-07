#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os.path

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
            [28141] | main() {
            [28141] | /* external-data: user message */
            [28141] |   a() {
            [28141] |     b() {
            [28141] |       c() {
   0.753 us [28141] |         getpid();
   1.430 us [28141] |       } /* c */
   1.915 us [28141] |     } /* b */
   2.405 us [28141] |   } /* a */
   3.005 us [28141] | } /* main */
""")

    def prerun(self, timeout):
        self.subcmd = 'record'
        self.option = ''
        self.exearg = 't-' + self.name

        record_cmd = TestBase.runcmd(self)
        self.pr_debug("prerun command: " + record_cmd)
        sp.call(record_cmd.split())

        self.subcmd = 'replay'
        self.option = '-F main -f time'
        self.exearg = ''
        replay_cmd = TestBase.runcmd(self)
        self.pr_debug("prerun command: " + replay_cmd)

        p = sp.Popen(replay_cmd.split(), stdout=sp.PIPE)
        if p.wait() != 0:
            return TestBase.TEST_NONZERO_RETURN

        output = p.communicate()[0].decode(errors='ignore')
        for l in output.split('\n'):
            if l.startswith('#'):
                continue;
            # parse first line to get the timestamp
            t = l.split(' | ')[0].strip()
            point = t.find('.')
            nsec = int(t[point+1:point+10])

            # add the external data right after the first line
            msg = '%s.%d %s\n' % (t[:point], nsec + 1, 'user message')

            data_file = open(os.path.join('uftrace.data', 'extern.dat'), 'w')
            data_file.write(msg)
            data_file.close()
            break
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'replay'
        self.option = ''
        self.exearg = ''

    def runcmd(self):
        cmd = TestBase.runcmd(self)
        return cmd.replace('--no-event', '')
