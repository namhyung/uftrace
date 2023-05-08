#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'file-var', """
s-file-var.py
# DURATION     TID     FUNCTION
            [539546] | __main__.<module>() {
            [539546] |   foo() {
  11.602 us [539546] |     posixpath.basename();
   9.202 us [539546] |     builtins.print();
  25.738 us [539546] |   } /* foo */
  28.985 us [539546] | } /* __main__.<module> */
""")
