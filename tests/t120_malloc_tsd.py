#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'malloc-tsd', ldflags='-pthread -ldl', result="""
# DURATION    TID     FUNCTION
            [ 5078] | main() {
   2.139 us [ 5078] |   pthread_key_create();
   0.391 us [ 5078] |   malloc();
   1.246 us [ 5078] |   pthread_setspecific();
  55.151 us [ 5078] |   pthread_create();
            [ 5078] |   pthread_join() {
            [ 5082] | thread() {
   0.803 us [ 5082] |   malloc();
   0.449 us [ 5082] |   pthread_setspecific();
   3.608 us [ 5082] | } /* thread */
 207.839 us [ 5078] |   } /* pthread_join */
   2.997 us [ 5078] |   pthread_getspecific();
            [ 5078] |   tsd_dtor() {
   0.646 us [ 5078] |     free();
   1.246 us [ 5078] |   } /* tsd_dtor */
   1.314 us [ 5078] |   pthread_key_delete();
 280.194 us [ 5078] | } /* main */
""")

    def setup(self):
        self.option = '-F main -F thread'
