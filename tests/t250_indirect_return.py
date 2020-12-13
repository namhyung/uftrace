#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'indirect-return', lang="C++", result="""
# DURATION    TID     FUNCTION
            [418122] | main() {
 178.233 us [418122] |   std::__cxx11::basic_ostringstream::basic_ostringstream();
   3.674 us [418122] |   std::__cxx11::basic_ostringstream::str();
   1.476 us [418122] |   std::__cxx11::basic_string::~basic_string();
  10.450 us [418122] |   std::__cxx11::basic_ostringstream::~basic_ostringstream();
 201.943 us [418122] | } /* main */
""", sort='simple')
