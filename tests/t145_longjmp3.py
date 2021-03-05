#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'longjmp3', """
# DURATION    TID     FUNCTION
   1.164 us [ 4107] | __monstartup();
   0.657 us [ 4107] | __cxa_atexit();
            [ 4107] | main() {
   0.705 us [ 4107] |   _setjmp() = 0;
   1.823 us [ 4107] |   getpid();
   0.182 us [ 4107] |   _setjmp() = 0;
            [ 4107] |   foo() {
            [ 4107] |     longjmp(1) {
   8.790 us [ 4107] |   } = 1; /* _setjmp */
   0.540 us [ 4107] |   getpid();
            [ 4107] |   bar() {
            [ 4107] |     baz() {
            [ 4107] |       longjmp(2) {
   1.282 us [ 4107] |   } = 2; /* _setjmp */
   0.540 us [ 4107] |   getpid();
            [ 4107] |   foo() {
            [ 4107] |     longjmp(3) {
   0.578 us [ 4107] |   } = 3; /* _setjmp */
            [ 4107] |   bar() {
            [ 4107] |     baz() {
            [ 4107] |       longjmp(4) {
   0.642 us [ 4107] |   } = 4; /* _setjmp */
  18.019 us [ 4107] | } /* main */
""")

    def setup(self):
        self.option = '-A .?longjmp@arg2 -R .?setjmp@retval'
