#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [17005] | _ZN2ns3ns13foo3barEv() {
            [17005] |   _ZN2ns3ns13foo4bar1Ev() {
            [17005] |     _ZN2ns3ns13foo4bar2Ev() {
            [17005] |       _ZN2ns3ns13foo4bar3Ev() {
   1.350 us [17005] |         malloc();
   3.245 us [17005] |       } /* _ZN2ns3ns13foo4bar3Ev */
   3.705 us [17005] |     } /* _ZN2ns3ns13foo4bar2Ev */
   4.128 us [17005] |   } /* _ZN2ns3ns13foo4bar1Ev */
   1.463 us [17005] |   free();
   6.702 us [17005] | } /* _ZN2ns3ns13foo3barEv */
""", sort='simple')

    def setup(self):
        self.option = '--demangle=no -F "_ZN2ns3ns13foo3barEv"'
