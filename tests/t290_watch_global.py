#!/usr/bin/env python3

import re

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'watch-global', result="""
# DURATION     TID     FUNCTION
            [243156] | __monstartup() {
            [243156] |   /* watch:var (mydata=0) */
   2.803 us [243156] | } /* __monstartup */
   0.621 us [243156] | __cxa_atexit();
            [243156] | main() {
            [243156] |   foo() {
            [243156] |     /* watch:var (mydata=1) */
   0.117 us [243156] |     bar();
            [243156] |     /* watch:var (mydata=2) */
   0.643 us [243156] |   } /* foo */
   0.938 us [243156] | } /* main */
""")

    def setup(self):
        self.option = '-W var:mydata'
