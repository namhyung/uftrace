#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
uftrace file header: magic         = 4674726163652100
uftrace file header: version       = 4
uftrace file header: header size   = 40
uftrace file header: endian        = 1 (little)
uftrace file header: class         = 2 (64 bit)
uftrace file header: features      = 0x363 (PLTHOOK | TASK_SESSION | SYM_REL_ADDR | MAX_STACK | PERF_EVENT | AUTO_ARGS)
uftrace file header: info          = 0x1bff

reading 5186.dat
58071.916834908   5186: [entry] main(400590) depth: 0
58071.916835853   5186: [entry] fork(400580) depth: 1
58071.917056572   5186: [exit ] fork(400580) depth: 1
58071.917091028   5186: [entry] wait(400570) depth: 1
58071.918038822   5186: [exit ] wait(400570) depth: 1
58071.918040938   5186: [entry] a(400774) depth: 1
58071.918041182   5186: [entry] b(400741) depth: 2
58071.918041482   5186: [entry] c(400706) depth: 3
58071.918042306   5186: [entry] getpid(400530) depth: 4
58071.918045615   5186: [exit ] getpid(400530) depth: 4
58071.918048103   5186: [exit ] c(400706) depth: 3
58071.918048457   5186: [exit ] b(400741) depth: 2
58071.918048760   5186: [exit ] a(400774) depth: 1
58071.918049117   5186: [exit ] main(400590) depth: 0
reading 5188.dat
""", sort='dump')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        import os.path
        t = 0
        for ln in open(os.path.join(TDIR, 'task.txt')):
            if not ln.startswith('TASK'):
                continue
            try:
                t = int(ln.split()[2].split('=')[1])
            except:
                pass
        if t == 0:
            return 'FAILED TO FIND TID'
        return '%s dump -d %s --tid %d' % (TestBase.uftrace_cmd, TDIR, t)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def fixup(self, cflags, result):
        import platform

        if platform.architecture()[0] == '32bit':
            result = result.replace("2 (64 bit)", "1 (32 bit)")
        p = sp.Popen(['file', 't-' + self.name], stdout=sp.PIPE)
        if 'BuildID' not in p.communicate()[0].decode(errors='ignore'):
            result = result.replace("0xbff", "0xbfd")
        return result
