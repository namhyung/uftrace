#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread-exit', ldflags='-pthread', result="""
1.000000
1.000000
# DURATION    TID     FUNCTION
            [26832] | main() {
            [26832] |   pthread_create() {
  51.697 us [26832] |   } /* pthread_create */
            [26832] |   pthread_create() {
  32.395 us [26832] |   } /* pthread_create */
            [26832] |   pthread_join() {
            [26836] | thread_main() {
            [26836] |   printf() {
  17.092 us [26836] |   } /* printf */
            [26836] |   pthread_exit() {
  12.943 us [26836] |   } /* pthread_exit */
            [26837] | thread_main() {
            [26837] |   printf() {
   5.480 us [26837] |   } /* printf */
            [26837] |   pthread_exit() {
   9.017 us [26837] |   } /* pthread_exit */
 362.442 us [26832] |   } /* pthread_join */
            [26832] |   pthread_join() {
   1.000 us [26832] |   } /* pthread_join */
 457.662 us [26832] | } /* main */
""")

    def setup(self):
        self.option = '--no-merge'
