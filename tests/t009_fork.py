#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
# DURATION    TID     FUNCTION
            [26125] | __cxa_atexit() {
  68.297 us [26125] | } /* __cxa_atexit */
            [26125] | main() {
            [26125] |   fork() {
 101.456 us [26125] |   } /* fork */
            [26125] |   wait() {
 298.356 us [26126] |   } /* fork */
            [26126] |   a() {
            [26126] |     b() {
            [26126] |       c() {
            [26126] |         getpid() {
   1.206 us [26126] |         } /* getpid */
   1.925 us [26126] |       } /* c */
   2.531 us [26126] |     } /* b */
   3.151 us [26126] |   } /* a */
 333.039 us [26126] | } /* main */
  19.376 us [26125] |   } /* wait */
            [26125] |   a() {
            [26125] |     b() {
            [26125] |       c() {
            [26125] |         getpid() {
   5.031 us [26125] |         } /* getpid */
   5.934 us [26125] |       } /* c */
   6.520 us [26125] |     } /* b */
   7.140 us [26125] |   } /* a */
 420.059 us [26125] | } /* main */
""")

    def setup(self):
        self.option = '--no-merge'
