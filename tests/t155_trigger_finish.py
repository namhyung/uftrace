#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
            [ 4131] | main() {
            [ 4131] |   a() {
            [ 4131] |     b() {
            [ 4131] |       c() {
            [ 4131] |         getpid() {
            [ 4131] |           /* linux:task-exit */

uftrace stopped tracing with remaining functions
================================================
task: 4131
[4] getpid
[3] c
[2] b
[1] a
[0] main
""")

    def setup(self):
        self.option = '-F main -T getpid@finish'


    def fixup(self, cflags, result):
        return result.replace("""         getpid() {
            [ 4131] |           /* linux:task-exit */""",
                                "         getpid() {")
