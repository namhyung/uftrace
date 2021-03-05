#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread', ldflags='-pthread', result="""
# DURATION    TID     FUNCTION
            [15156] | main() {
            [15156] |   pthread_create() {
  47.998 us [15156] |   } /* pthread_create */
            [15156] |   pthread_create() {
  49.997 us [15156] |   } /* pthread_create */
            [15156] |   pthread_create() {
  86.359 us [15156] |   } /* pthread_create */
            [15156] |   pthread_create() {
 135.596 us [15156] |   } /* pthread_create */
            [15156] |   pthread_join() {
            [15158] |         foo() {
            [15158] |           a() {
            [15158] |             b() {
            [15158] |               c() {
   2.563 us [15158] |               } /* c */
   2.977 us [15158] |             } /* b */
   3.288 us [15158] |           } /* a */
   4.093 us [15158] |         } /* foo */
            [15159] |                 foo() {
            [15159] |                   a() {
            [15159] |                     b() {
            [15159] |                       c() {
   0.256 us [15159] |                       } /* c */
   0.580 us [15159] |                     } /* b */
   0.938 us [15159] |                   } /* a */
   1.540 us [15159] |                 } /* foo */
 195.074 us [15156] |   } /* pthread_join */
            [15156] |   pthread_join() {
  19.243 us [15156] |   } /* pthread_join */
            [15156] |   pthread_join() {
            [15160] |                         foo() {
            [15160] |                           a() {
            [15160] |                             b() {
            [15160] |                               c() {
   0.226 us [15160] |                               } /* c */
   0.587 us [15160] |                             } /* b */
   0.948 us [15160] |                           } /* a */
   1.429 us [15160] |                         } /* foo */
  93.036 us [15156] |   } /* pthread_join */
            [15156] |   pthread_join() {
            [15161] |                                 foo() {
            [15161] |                                   a() {
            [15161] |                                     b() {
            [15161] |                                       c() {
   0.196 us [15161] |                                       } /* c */
   0.587 us [15161] |                                     } /* b */
   0.983 us [15161] |                                   } /* a */
   1.796 us [15161] |                                 } /* foo */
   1.358 ms [15156] |   } /* pthread_join */
   1.995 ms [15156] | } /* main */
""")

    def setup(self):
        self.option = '--column-view --column-offset=4 --no-merge'
