#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [32537] | main(1) {
            [32537] |   foo() {
            [32537] |     bar() {
   2.080 ms [32537] |       usleep(2000);
   2.084 ms [32537] |     } /* bar */
   2.102 ms [32537] |   } /* foo */
   2.103 ms [32537] | } /* main */
""", sort='simple')

    def build(self, name, cflags='', ldflags=''):
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def prepare(self):
        self.subcmd  = "record"
        self.option  = "-A main@arg1 "
        self.option += "-A (malloc|free|usleep)@plt,arg1 "
        self.option += "-R malloc@retval"
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-t 1ms'
