#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'nested', result="""
# DURATION    TID     FUNCTION
            [13348] | main() {
            [13348] |   foo() {
   0.170 us [13348] |     foo_internal.2406();
   0.650 us [13348] |   } /* foo */
            [13348] |   bar() {
            [13348] |     qsort() {
   0.120 us [13348] |       compar.2414();
   0.093 us [13348] |       compar.2414();
   0.092 us [13348] |       compar.2414();
   2.479 us [13348] |     } /* qsort */
   3.462 us [13348] |   } /* bar */
   3.623 us [13348] | } /* main */
""")

    def sort(self, output, ignore_children=False):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        before_main = True
        funcs = []
        for ln in output.split('\n'):
            if ln.find(' | main()') > 0:
                before_main = False
            if before_main:
                continue
            # ignore result of remaining functions which follows a blank line
            if ln.strip() == '':
                break;

            try:
                func = ln.split('|', 1)[-1]
                # ignore function suffix after '.'
                funcs.append(func.split('.',1)[0])
            except:
                pass

        result = '\n'.join(funcs)
        return result
