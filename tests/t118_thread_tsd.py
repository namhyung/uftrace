#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread-tsd', ldflags='-pthread', result="""
# DURATION    TID     FUNCTION
   1.368 us [ 3336] | __monstartup();
   1.142 us [ 3336] | __cxa_atexit();
            [ 3336] | main() {
   1.019 us [ 3336] |   pthread_key_create();
   1.278 us [ 3336] |   malloc();
   0.828 us [ 3336] |   pthread_setspecific();
  39.549 us [ 3336] |   pthread_create();
            [ 3336] |   pthread_join() {
            [ 3346] | thread() {
   0.804 us [ 3346] |   malloc();
   0.128 us [ 3346] |   pthread_setspecific();
   2.708 us [ 3346] | } /* thread */
 149.452 us [ 3336] |   } /* pthread_join */
   1.684 us [ 3336] |   pthread_getspecific();
   0.549 us [ 3336] |   tsd_dtor();
   0.861 us [ 3336] |   pthread_key_delete();
 199.848 us [ 3336] | } /* main */
""")

    def fixup(self, cflags, result):
        return result.replace('tsd_dtor();', """tsd_dtor() {
   0.347 us [ 3336] |     free();
   0.549 us [ 3336] |   } /* tsd_dtor */""")
