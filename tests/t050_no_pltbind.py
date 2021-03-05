#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'racycount', ldflags='-pthread', result="""
# DURATION    TID     FUNCTION
            [22829] | __monstartup() {
  17.753 us [22829] | } /* __monstartup */
            [22829] | __cxa_atexit() {
   8.038 us [22829] | } /* __cxa_atexit */
            [22829] | main() {
            [22829] |   pthread_barrier_init() {
   6.095 us [22829] |   } /* pthread_barrier_init */
            [22829] |   pthread_create() {
  81.734 us [22829] |   } /* pthread_create */
            [22829] |   pthread_create() {
  85.171 us [22829] |   } /* pthread_create */
            [22829] |   racy_count() {
            [22829] |     pthread_barrier_wait() {
            [22832] |                 thread_fn() {
            [22832] |                   racy_count() {
            [22831] |                                 thread_fn() {
            [22832] |                     pthread_barrier_wait() {
            [22831] |                                   racy_count() {
            [22831] |                                     pthread_barrier_wait() {
  21.614 us [22831] |                                     } /* pthread_barrier_wait */
 246.706 us [22829] |     } /* pthread_barrier_wait */
  78.105 us [22832] |                     } /* pthread_barrier_wait */
 300.416 us [22831] |                                   } /* racy_count */
 314.149 us [22831] |                                 } /* thread_fn */
 567.337 us [22829] |   } /* racy_count */
            [22829] |   pthread_join() {
 370.700 us [22832] |                   } /* racy_count */
 383.658 us [22832] |                 } /* thread_fn */
 334.627 us [22829] |   } /* pthread_join */
            [22829] |   pthread_join() {
   5.735 us [22829] |   } /* pthread_join */
   1.122 ms [22829] | } /* main */
""")

    def setup(self):
        self.option = '--no-pltbind --column-view --no-merge'
