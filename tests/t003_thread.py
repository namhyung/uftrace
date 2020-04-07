#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread', ldflags='-pthread', result="""
# DURATION    TID     FUNCTION
            [ 1429] | main() {
            [ 1429] |   pthread_create() {
  44.296 us [ 1429] |   } /* pthread_create */
            [ 1429] |   pthread_create() {
  24.726 us [ 1429] |   } /* pthread_create */
            [ 1429] |   pthread_create() {
  21.086 us [ 1429] |   } /* pthread_create */
            [ 1429] |   pthread_create() {
  20.720 us [ 1429] |   } /* pthread_create */
            [ 1429] |   pthread_join() {
            [ 1430] | foo() {
            [ 1430] |   a() {
            [ 1430] |     b() {
            [ 1430] |       c() {
   2.880 us [ 1430] |       } /* c */
   3.793 us [ 1430] |     } /* b */
   4.620 us [ 1430] |   } /* a */
  96.966 us [ 1430] | } /* foo */
 340.217 us [ 1429] |   } /* pthread_join */
            [ 1429] |   pthread_join() {
            [ 1431] | foo() {
            [ 1431] |   a() {
            [ 1431] |     b() {
            [ 1431] |       c() {
   0.444 us [ 1431] |       } /* c */
   1.333 us [ 1431] |     } /* b */
   2.186 us [ 1431] |   } /* a */
  63.205 us [ 1431] | } /* foo */
 100.046 us [ 1429] |   } /* pthread_join */
            [ 1429] |   pthread_join() {
            [ 1432] | foo() {
            [ 1432] |   a() {
            [ 1432] |     b() {
            [ 1432] |       c() {
   0.420 us [ 1432] |       } /* c */
   1.210 us [ 1432] |     } /* b */
   2.134 us [ 1432] |   } /* a */
 169.879 us [ 1432] | } /* foo */
  27.470 us [ 1429] |   } /* pthread_join */
            [ 1429] |   pthread_join() {
            [ 1433] | foo() {
            [ 1433] |   a() {
            [ 1433] |     b() {
            [ 1433] |       c() {
   0.577 us [ 1433] |       } /* c */
   1.717 us [ 1433] |     } /* b */
   2.860 us [ 1433] |   } /* a */
 121.139 us [ 1433] | } /* foo */
   0.390 us [ 1429] |   } /* pthread_join */
 658.759 us [ 1429] | } /* main */
""")

    def setup(self):
        self.option = '--no-merge'
