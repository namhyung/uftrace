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

uftrace stopped tracing with remaining functions
================================================
task: 4131
[4] getpid
[3] c
[2] b
[1] a
[0] main
""")

    def runcmd(self):
        uftrace = TestBase.ftrace
        options = '-F main -T getpid@finish'
        program = 't-' + self.name
        return '%s %s %s' % (uftrace, options, program)
