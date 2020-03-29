#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', """
# DURATION    TID     FUNCTION
   1.811 us [18130] | getpid();
   1.776 us [18130] | getsid();
   1.289 us [18130] | getuid();
   1.043 us [18130] | getgid();
""", sort='simple')

    def setup(self):
        self.option = '-F "get.?id@plt"'
