#!/usr/bin/env python

import re
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [18229] | bar() {
   2.078 ms [18229] |   usleep();
   2.080 ms [18229] | } /* bar */
""")

    def runcmd(self):
        return '%s -r 1ms -F bar %s' % (TestBase.ftrace, 't-' + self.name)
