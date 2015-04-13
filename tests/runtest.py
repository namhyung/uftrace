#!/usr/bin/env python

import os, sys
import glob, re
import subprocess as sp

class TestBase:
    supported_lang = {
        'C':   { 'cc': 'gcc', 'flags': 'CFLAGS',   'ext': '.c' },
        'C++': { 'cc': 'g++', 'flags': 'CXXFLAGS', 'ext': '.cpp' },
    }

    TEST_SUCCESS = 0
    TEST_UNSUPP_LANG = -1
    TEST_BUILD_FAIL = -2
    TEST_ABNORMAL_EXIT = -3
    TEST_TIME_OUT = -4
    TEST_DIFF_RESULT = -5
    TEST_NONZERO_RETURN = -6

    ftrace = '../ftrace -L ..'

    def __init__(self, name, result, lang='C', cflags='', ldflags=''):
        self.name = name
        self.result = result
        self.cflags = cflags
        self.ldflags = ldflags
        self.lang = lang

    def build(self, cflags='', ldflags=''):
        if self.lang not in TestBase.supported_lang:
#            print("%s: unsupported language: %s" % (self.name, self.lang))
            return TestBase.TEST_UNSUPP_LANG

        lang = TestBase.supported_lang[self.lang]
        prog = 't-' + self.name
        src  = 's-' + self.name + lang['ext']

        build_cflags  = ' '.join([self.cflags, cflags, \
                                  os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, \
                                  os.getenv('LDFLAGS', '')])

        build_cmd = '%s -o %s %s %s %s' % \
                    (lang['cc'], prog, build_cflags, src, build_ldflags)

#        print("build command:", build_cmd)
        return sp.call(build_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)

    def runcmd(self):
        """ This function returns (shell) command that runs the test.
            A test case can extend this to setup a complex configuration.  """
        return '%s %s' % (TestBase.ftrace, 't-' + self.name)

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        pids = {}
        order = 1
        before_main = True
        for ln in output.split('\n'):
            if ln.find(' | main()') > 0:
                before_main = False
            if before_main:
                continue
            # ignore result of remaining functions which follows a blank line
            if ln.strip() == '':
                break;
            pid_patt = re.compile('[^[]*\[ *(\d+)\] |')
            m = pid_patt.match(ln)
            try:
                pid = int(m.group(1))
            except:
                continue

            func = ln.split('|', 1)[-1]
            if pid not in pids:
                pids[pid] = { 'order': order }
                pids[pid]['result'] = []
                order += 1
            pids[pid]['result'].append(func)

        result = ''
        pid_list = sorted(list(pids), key=lambda p: pids[p]['order'])
        for p in pid_list:
            result += '\n'.join(pids[p]['result'])
        return result

    def run(self):
        test_cmd = self.runcmd()
#        print("test command: %s" % test_cmd)

        p = sp.Popen(test_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)

        timed_out = False
        def timeout(sig, frame):
            timed_out = True
            p.kill()

        import signal
        signal.signal(signal.SIGALRM, timeout)

        result_expect = self.sort(self.result)
        signal.alarm(2)
        result_tested = self.sort(p.communicate()[0].decode())  # for python3
        signal.alarm(0)

        ret = p.wait()
        if ret < 0:
            if timed_out:
                return TestBase.TEST_TIME_OUT
            else:
                return TestBase.TEST_ABNORMAL_EXIT
        if ret > 0:
            return TestBase.TEST_NONZERO_RETURN

#        print(result_expect)
#        print(result_tested)

        if result_expect != result_tested:
            return TestBase.TEST_DIFF_RESULT

        return 0


trace_flags = ['-finstrument-functions', '-pg']
optimizations = ['-O0', '-O1', '-O2', '-O3', '-Os', '-Og']

RED     = '\033[1;31m'
GREEN   = '\033[1;32m'
YELLOW  = '\033[1;33m'
NORMAL  = '\033[0m'

colored_result = {
    TestBase.TEST_SUCCESS:        GREEN  + 'OK' + NORMAL,
    TestBase.TEST_UNSUPP_LANG:    YELLOW + 'LA' + NORMAL,
    TestBase.TEST_BUILD_FAIL:     YELLOW + 'BI' + NORMAL,
    TestBase.TEST_ABNORMAL_EXIT:  YELLOW + 'SG' + NORMAL,
    TestBase.TEST_TIME_OUT:       YELLOW + 'TM' + NORMAL,
    TestBase.TEST_DIFF_RESULT:    RED    + 'NG' + NORMAL,
    TestBase.TEST_NONZERO_RETURN: YELLOW + 'NZ' + NORMAL,
}

text_result = {
    TestBase.TEST_SUCCESS:        'OK',
    TestBase.TEST_UNSUPP_LANG:    'LA',
    TestBase.TEST_BUILD_FAIL:     'BI',
    TestBase.TEST_ABNORMAL_EXIT:  'SG',
    TestBase.TEST_TIME_OUT:       'TM',
    TestBase.TEST_DIFF_RESULT:    'NG',
    TestBase.TEST_NONZERO_RETURN: 'NZ',
}

result_string = {
    TestBase.TEST_SUCCESS:        'OK: Test succeeded',
    TestBase.TEST_UNSUPP_LANG:    'LA: Unsupported Language',
    TestBase.TEST_BUILD_FAIL:     'BI: Build failed',
    TestBase.TEST_ABNORMAL_EXIT:  'SG: Abnormal exit by signal',
    TestBase.TEST_TIME_OUT:       'TM: Test ran too long',
    TestBase.TEST_DIFF_RESULT:    'NG: Different test result',
    TestBase.TEST_NONZERO_RETURN: 'NZ: Non-zero return value',
}

def run_single_case(case):
    result = {}

    # for python3
    _locals = locals()
    exec("import %s; tc = %s.TestCase()" % (case, case), globals(), _locals)
    tc = _locals['tc']

    for flag in trace_flags:
        for opt in optimizations:
            cflags = ' '.join([flag, opt])
            if tc.build(cflags) != 0:
                ret = TestBase.TEST_BUILD_FAIL
            else:
                ret = tc.run()
            result[cflags] = ret

    return result

def print_test_result(case, result):
    cflags = sorted(list(result))
    if sys.stdout.isatty():
        result_list = [colored_result[result[f]] for f in cflags]
    else:
        result_list = [text_result[result[f]] for f in cflags]

    output = case[1:4]
    output += ' %-16s' % case[5:] + ': ' + ' '.join(result_list) + '\n'
    sys.stdout.write(output)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: runtest.py <testcase>")
        sys.exit(1)

    opts = ' '.join(sorted([o[1:] for o in optimizations]))
    optslen = len(opts);

    header1 = '%-20s ' % 'Test case'
    header2 = '-' * 20 + ':'
    empty = '                      '

    for flags in sorted(trace_flags):
        # align with optimization flags
        header1 += ' ' + flags[:optslen] + empty[len(flags):optslen]
        header2 += ' ' + opts

    print(header1)
    print(header2)

    if sys.argv[1] != 'all':
        try:
            testcase = glob.glob('t*' + sys.argv[1] + '*.py')[0][:-3]
        except:
            print("cannot find testcase for : %s" % sys.argv[1])
            sys.exit(1)
        result = run_single_case(testcase)
        print_test_result(testcase, result)
    else:
        testcases = sorted(glob.glob('t???_*.py'))
        for tc in testcases:
            name = tc[:-3]  # remove '.py'
            result = run_single_case(name)
            print_test_result(name, result)
