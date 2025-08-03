#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'libexcept-main', lang='C++', result="""
# DURATION    TID     FUNCTION
            [423633] | main() {
            [423633] |   XXX::XXX() {
  30.679 us [423633] |     XXX::XXX();
  31.490 us [423633] |   } /* XXX::XXX */
            [423633] |   YYY::YYY() {
   0.509 us [423633] |     __cxa_allocate_exception();
   0.541 us [423633] |     std::runtime_error::runtime_error();
   5.670 us [423633] |   } /* YYY::YYY */
  42.354 us [423633] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        if TestBase.build_libfoo(self, 'except', cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-libexcept-main.cpp', ['libexcept.so'],
                                      cflags, ldflags)

    def setup(self):
        # Destructor is non-deterministric, let's skip it.
        self.option = '-N "~runtime_error$"'
