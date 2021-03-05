#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION [SOURCE]
   0.678 us [ 19939] | __monstartup();
   0.234 us [ 19939] | __cxa_atexit();
            [ 19939] | main() { /* tests/s-abc.c:26 */
            [ 19939] |   a() { /* tests/s-abc.c:11 */
            [ 19939] |     b() { /* tests/s-abc.c:16 */
            [ 19939] |       c() { /* tests/s-abc.c:21 */
   1.120 us [ 19939] |         getpid();
   1.697 us [ 19939] |       } /* c at tests/s-abc.c:21 */
   2.044 us [ 19939] |     } /* b at tests/s-abc.c:16 */
   2.329 us [ 19939] |   } /* a at tests/s-abc.c:11 */
   2.644 us [ 19939] | } /* main at tests/s-abc.c:26 */
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def prepare(self):
        self.subcmd = 'record'
        self.option = '--srcline'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '--srcline'

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        before_main = True
        for ln in output.split('\n'):
            if ln.find(' | main()') > 0:
                before_main = False
            if before_main:
                continue
            # ignore result of remaining functions which follows a blank line
            if ln.strip() == '':
                break

            func = ln.split('|', 1)[-1].split('/*')

            if len(func) < 2 :
                result.append('%s' % (func[0]))
            else :
                result.append('%s %s' % (func[-2], func[-1][0:-3].split('/')[-1]))

        return '\n'.join(result)
