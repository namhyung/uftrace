#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
uftrace file header: magic         = 4674726163652100
uftrace file header: version       = 4
uftrace file header: header size   = 40
uftrace file header: endian        = 1 (little)
uftrace file header: class         = 2 (64 bit)
uftrace file header: features      = 0x63
uftrace file header: info          = 0x3ff

reading 5231.dat
58348.873444506   5231: [entry] main(400512) depth: 0
58348.873444843   5231: [entry] a(4006b2) depth: 1
58348.873445107   5231: [entry] b(4006a0) depth: 2
58348.873448707   5231: [exit ] b(4006a0) depth: 2
58348.873448996   5231: [exit ] a(4006b2) depth: 1
58348.873449309   5231: [exit ] main(400512) depth: 0
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s dump -d %s -F main -N c' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        import re

        mode = 1
        patt = re.compile(r'[^[]*(?P<type>\[(entry|exit )\]) (?P<func>[_a-z0-9]*)\([0-9a-f]+\) (?P<depth>.*)')
        result = []
        for ln in output.split('\n'):
            if ln.startswith('uftrace'):
                result.append(ln)
            else:
                m = patt.match(ln)
                if m is None:
                    continue
                result.append(patt.sub(r'\g<type> \g<depth> \g<func>', ln))

        return '\n'.join(result)
