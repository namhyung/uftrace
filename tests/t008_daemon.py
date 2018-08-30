#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'daemon', """
# DURATION    TID     FUNCTION
  71.636 us [28239] | __cxa_atexit();
            [28239] | main() {
            [28239] |   daemon() {
 393.995 us [28240] |   } /* daemon */
            [28240] |   a() {
            [28240] |     b() {
            [28240] |       c() {
  19.127 us [28240] |         getpid();
  20.230 us [28240] |       } /* c */
  20.870 us [28240] |     } /* b */
  21.633 us [28240] |   } /* a */
 427.945 us [28240] | } /* main */

ftrace stopped tracing with remaining functions
===============================================
task: 28239
[1] daemon
[0] main

""")
