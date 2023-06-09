#!/usr/bin/env python

from runtest import PyTestBase

# json.dumps() might be implemented differently depending on versions
class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'libmain', """
# DURATION     TID     FUNCTION
            [ 12889] | __main__.<module>() {
            [ 12889] |   myfunc() {
            [ 12889] |     mymod.public_func() {
            [ 12889] |       mymod.internal() {
            [ 12889] |         json.dumps() {
  16.521 us [ 12889] |           json.encoder.JSONEncoder.encode();
  19.719 us [ 12889] |         } /* json.dumps */
  23.313 us [ 12889] |       } /* mymod.internal */
            [ 12889] |       mymod.internal() {
            [ 12889] |         json.dumps() {
   6.233 us [ 12889] |           json.encoder.JSONEncoder.encode();
   7.311 us [ 12889] |         } /* json.dumps */
   8.484 us [ 12889] |       } /* mymod.internal */
  34.855 us [ 12889] |     } /* mymod.public_func */
  37.884 us [ 12889] |   } /* myfunc */
  10.610 ms [ 12889] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '--nest-libcall -N ^importlib -D 6'

    def fixup(self, cflags, result):
        return result.replace(".JSONEncoder", "")
