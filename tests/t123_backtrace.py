#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'backtrace', lang='C++', result="""
# DURATION    TID     FUNCTION
   2.277 us [11616] | __cxa_atexit();
            [11616] | main() {
            [11616] |   a() {
            [11616] |     b() {
            [11616] |       c() {
            [11616] |         foo() {
  51.142 us [11616] |           backtrace();
  52.363 us [11616] |         } /* foo */
  52.735 us [11616] |       } /* c */
  53.031 us [11616] |     } /* b */
  53.317 us [11616] |   } /* a */
  53.703 us [11616] | } /* main */
""")
