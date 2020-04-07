#!/usr/bin/env python

from runtest import TestBase
import os

class TestCase(TestBase):
    """This tests when dlopen() loads multiple libraries (libbar and libbaz)
       at once.  The Parent code is in libbar while Child is in libbaz."""
    def __init__(self):
        TestBase.__init__(self, 'dlopen2', lang="C++", result="""
# DURATION     TID     FUNCTION
            [ 29510] | main() {
 398.509 us [ 29510] |   dlopen();
   2.324 us [ 29510] |   dlsym();
            [ 29510] |   creat() {
            [ 29510] |     Child::Child() {
   0.290 us [ 29510] |       Parent::Parent();
   1.703 us [ 29510] |     } /* Child::Child */
   6.090 us [ 29510] |   } /* creat */
   0.133 us [ 29510] |   Child::func();
  48.519 us [ 29510] |   dlclose();
 465.432 us [ 29510] | } /* main */
""")
        os.environ['LD_LIBRARY_PATH'] = "."

    def build(self, name, cflags='', ldflags=''):
        if TestBase.build_libfoo(self, 'bar', cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        if TestBase.build_libfoo(self, 'baz', cflags, ldflags + ' -L. -lbar') != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-dlopen2.cpp', ['libdl.so'],
                                      cflags, ldflags)

    def setup(self):
        self.option = '-F a'
