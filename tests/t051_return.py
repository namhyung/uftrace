#!/usr/bin/env python

from runtest import TestBase


class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(
            self,
            "return",
            result="""
# DURATION    TID     FUNCTION
            [12703] | main() {
            [12703] |   return_large() {
   1.440 us [12703] |     memset();
   2.533 us [12703] |   } /* return_large */
   0.153 us [12703] |   return_small();
   0.157 us [12703] |   return_long_double();
   4.097 us [12703] | } /* main */
""",
        )

    def setup(self):
        # to avoid unexpected memcpy in aarch64
        self.option = "-N memcpy "
