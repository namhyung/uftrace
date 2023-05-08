#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'sleep', """
# DURATION     TID     FUNCTION
            [538338] | __main__.<module>() {
            [538338] |   foo() {
 100.152 ms [538338] |     time.sleep();
 100.208 ms [538338] |   } /* foo */
 100.215 ms [538338] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '-t 80ms'
