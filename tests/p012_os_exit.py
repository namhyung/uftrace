#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'abc-exit', """
# DURATION     TID     FUNCTION
            [  6461] | __main__.<module>() {
            [  6461] |   a() {
            [  6461] |     b() {
            [  6461] |       c() {
   1.114 us [  6461] |         posix.getpid();
   4.746 us [  6461] |       } /* c */
   7.101 us [  6461] |     } /* b */
   9.897 us [  6461] |   } /* a */

uftrace stopped tracing with remaining functions
================================================
task: 6461
[0] __main__.<module>
""", sort='task')
