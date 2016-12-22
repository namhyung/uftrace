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
    TEST_SKIP = -7
    TEST_SUCCESS_FIXED = -8

    objdir = 'objdir' in os.environ and os.environ['objdir'] or '..'
    ftrace = objdir + '/uftrace --no-pager -L' + objdir

    default_cflags = ['-fno-inline', '-fno-builtin', '-fno-omit-frame-pointer']

    def __init__(self, name, result, lang='C', cflags='', ldflags='', sort='task'):
        self.name = name
        self.result = result
        self.cflags = cflags
        self.ldflags = ldflags
        self.lang = lang
        self.sort_method = sort

    def set_debug(self, dbg):
        self.debug = dbg

    def pr_debug(self, msg):
        if self.debug:
            print(msg)

    def build(self, cflags='', ldflags=''):
        if self.lang not in TestBase.supported_lang:
            pr_debug("%s: unsupported language: %s" % (self.name, self.lang))
            return TestBase.TEST_UNSUPP_LANG

        lang = TestBase.supported_lang[self.lang]
        prog = 't-' + self.name
        src  = 's-' + self.name + lang['ext']

        build_cflags  = ' '.join(TestBase.default_cflags + [self.cflags, cflags, \
                                  os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, \
                                  os.getenv('LDFLAGS', '')])

        build_cmd = '%s -o %s %s %s %s' % \
                    (lang['cc'], prog, build_cflags, src, build_ldflags)

        self.pr_debug("build command: %s" % build_cmd)
        try:
            return sp.call(build_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)
        except:
            return TestBase.TEST_BUILD_FAIL

    def runcmd(self):
        """ This function returns (shell) command that runs the test.
            A test case can extend this to setup a complex configuration.  """
        return '%s %s' % (TestBase.ftrace, 't-' + self.name)

    def task_sort(self, output, ignore_children=False):
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

        try:
            if ignore_children:
                result += '\n'.join(pids[pid_list[0]]['result'])
            else:
                for p in pid_list:
                    result += '\n'.join(pids[p]['result'])
        except:
            pass  # this leads to a failure with 'NG'
        return result

    def simple_sort(self, output, ignored):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            func = ln.split('|', 1)[-1]
            result.append(func)

        return '\n'.join(result)

    def report_sort(self, output, ignored):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue
            line = ln.split()
            if line[0] == 'Total':
                continue
            if line[0].startswith('='):
                continue
            # A report line consists of following data
            # [0]         [1]   [2]        [3]   [4]     [5]
            # total_time  unit  self_time  unit  called  function
            if line[5].startswith('__'):
                continue
            result.append('%s %s' % (line[4], line[5]))

        return '\n'.join(result)

    def graph_sort(self, output, ignored):
        """ This function post-processes output of the test to be compared.
            It ignores blank and comment (#) lines and header lines.  """
        result = []
        mode = 0
        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#') or ln.startswith('='):
                continue
            # A graph result consists of backtrace and calling functions
            if ln.startswith('backtrace'):
                mode = 1
                continue
            if ln.startswith('calling'):
                mode = 2
                continue
            if mode == 1:
                if ln.startswith(' backtrace #'):
                    result.append(ln.split(',')[0])  # remove time part
                if ln.startswith('   ['):
                    result.append(ln.split('(')[0])  # remove '(addr)' part
            if mode == 2:
                result.append(ln.split(':')[1])      # remove time part

        return '\n'.join(result)

    def sort(self, output, ignore_children=False):
        if not TestBase.__dict__.has_key(self.sort_method + '_sort'):
            print('cannot find the sort function: %s' % self.sort_method)
            return ''  # this leads to a failure with 'NG'
        func = TestBase.__dict__[self.sort_method + '_sort']
        if callable(func):
            return func(self, output, ignore_children)
        else:
            return ''  # this leads to a failure with 'NG'

    def pre(self):
        """This function is called before running a testcase"""
        return TestBase.TEST_SUCCESS

    def post(self, result):
        """This function is called after running a testcase"""
        return result

    def fixup(self, cflags, result):
        """This function is called when result is different to expected.
           But if we know some known difference on some optimization level,
           apply it and re-test with the modified result."""
        return result

    def run(self, name, cflags, diff):
        ret = TestBase.TEST_SUCCESS

        test_cmd = self.runcmd()
        self.pr_debug("test command: %s" % test_cmd)

        p = sp.Popen(test_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)

        timed_out = False
        def timeout(sig, frame):
            timed_out = True
            p.kill()

        import signal
        signal.signal(signal.SIGALRM, timeout)

        result_expect = self.sort(self.result)
        signal.alarm(5)
        result_origin = p.communicate()[0].decode()
        result_tested = self.sort(result_origin)  # for python3
        signal.alarm(0)

        ret = p.wait()
        if ret < 0:
            if timed_out:
                return TestBase.TEST_TIME_OUT
            else:
                return TestBase.TEST_ABNORMAL_EXIT
        if ret > 0:
            return TestBase.TEST_NONZERO_RETURN

        self.pr_debug("=========== %s =============\n%s" % ("expected", result_expect))
        self.pr_debug("=========== %s =============\n%s" % ("original", result_origin))
        self.pr_debug("=========== %s =============\n%s" % ("result", result_tested))

        if result_expect.strip() == '':
            return TestBase.TEST_DIFF_RESULT

        if result_expect != result_tested:
            result_expect = self.sort(self.fixup(cflags, self.result))
            ret = TestBase.TEST_SUCCESS_FIXED

        if result_expect != result_tested:
            if diff:
                f = open('expect', 'w')
                f.write(result_expect + '\n')
                f.close()
                f = open('result', 'w')
                f.write(result_tested + '\n')
                f.close()
                p = sp.Popen(['diff', '-U1', 'expect', 'result'], stdout=sp.PIPE)
                print("%s: diff result of %s" % (name, cflags))
                print(p.communicate()[0].decode())
                os.remove('expect')
                os.remove('result')
            return TestBase.TEST_DIFF_RESULT

        return ret


RED     = '\033[1;31m'
GREEN   = '\033[1;32m'
YELLOW  = '\033[1;33m'
NORMAL  = '\033[0m'

colored_result = {
    TestBase.TEST_SUCCESS:        GREEN  + 'OK' + NORMAL,
    TestBase.TEST_UNSUPP_LANG:    YELLOW + 'LA' + NORMAL,
    TestBase.TEST_BUILD_FAIL:     YELLOW + 'BI' + NORMAL,
    TestBase.TEST_ABNORMAL_EXIT:  RED    + 'SG' + NORMAL,
    TestBase.TEST_TIME_OUT:       YELLOW + 'TM' + NORMAL,
    TestBase.TEST_DIFF_RESULT:    RED    + 'NG' + NORMAL,
    TestBase.TEST_NONZERO_RETURN: YELLOW + 'NZ' + NORMAL,
    TestBase.TEST_SKIP:           YELLOW + 'SK' + NORMAL,
    TestBase.TEST_SUCCESS_FIXED:  YELLOW + 'OK' + NORMAL,
}

text_result = {
    TestBase.TEST_SUCCESS:        'OK',
    TestBase.TEST_UNSUPP_LANG:    'LA',
    TestBase.TEST_BUILD_FAIL:     'BI',
    TestBase.TEST_ABNORMAL_EXIT:  'SG',
    TestBase.TEST_TIME_OUT:       'TM',
    TestBase.TEST_DIFF_RESULT:    'NG',
    TestBase.TEST_NONZERO_RETURN: 'NZ',
    TestBase.TEST_SKIP:           'SK',
    TestBase.TEST_SUCCESS_FIXED:  'OK',
}

result_string = {
    TestBase.TEST_SUCCESS:        'OK: Test succeeded',
    TestBase.TEST_UNSUPP_LANG:    'LA: Unsupported Language',
    TestBase.TEST_BUILD_FAIL:     'BI: Build failed',
    TestBase.TEST_ABNORMAL_EXIT:  'SG: Abnormal exit by signal',
    TestBase.TEST_TIME_OUT:       'TM: Test ran too long',
    TestBase.TEST_DIFF_RESULT:    'NG: Different test result',
    TestBase.TEST_NONZERO_RETURN: 'NZ: Non-zero return value',
    TestBase.TEST_SKIP:           'SK: Skipped',
    TestBase.TEST_SUCCESS_FIXED:  'OK: Test almost succeeded',
}

def run_single_case(case, flags, opts, diff, dbg):
    result = []

    # for python3
    _locals = locals()
    exec("import %s; tc = %s.TestCase()" % (case, case), globals(), _locals)
    tc = _locals['tc']
    tc.set_debug(dbg)

    for flag in flags:
        for opt in opts:
            cflags = ' '.join(["-" + flag, "-" + opt])
            ret = tc.build(cflags)
            if ret == TestBase.TEST_SUCCESS:
                ret = tc.pre()
                if ret == TestBase.TEST_SUCCESS:
                    ret = tc.run(case, cflags, diff)
                    ret = tc.post(ret)
            result.append(ret)

    return result

def print_test_result(case, result):
    if sys.stdout.isatty():
        result_list = [colored_result[r] for r in result]
    else:
        result_list = [text_result[r] for r in result]

    output = case[1:4]
    output += ' %-16s' % case[5:] + ': ' + ' '.join(result_list) + '\n'
    sys.stdout.write(output)


def parse_argument():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--profile-flags", dest='flags',
                        default="pg finstrument-functions",
                        help="comma separated list of compiler profiling flags")
    parser.add_argument("-O", "--optimize-levels", dest='opts', default="0123s",
                        help="compiler optimization levels")
    parser.add_argument("case", nargs='?', default="all",
                        help="test case: 'all' or test number or (partial) name")
    parser.add_argument("-p", "--profile-pg", dest='pg_flag', action='store_true',
                        help="profiling with -pg option")
    parser.add_argument("-i", "--instrument-functions", dest='if_flag', action='store_true',
                        help="profiling with -finstrument-functions option")
    parser.add_argument("-d", "--diff", dest='diff', action='store_true',
                        help="show diff result if not matched")
    parser.add_argument("-v", "--verbose", dest='debug', action='store_true',
                        help="show internal command and result for debugging")

    return parser.parse_args()

if __name__ == "__main__":
    arg = parse_argument()

    opts = ' '.join(sorted(['O'+o for o in arg.opts]))
    optslen = len(opts);

    header1 = '%-20s ' % 'Test case'
    header2 = '-' * 20 + ':'
    empty = '                      '

    if arg.pg_flag:
        flags = ['pg']
    elif arg.if_flag:
        flags = ['finstrument-functions']
    else:
        flags = arg.flags.split()
    for flag in flags:
        # align with optimization flags
        header1 += ' ' + flag[:optslen] + empty[len(flag):optslen]
        header2 += ' ' + opts

    print(header1)
    print(header2)

    if arg.case == 'all':
        testcases = sorted(glob.glob('t???_*.py'))
        for tc in testcases:
            name = tc[:-3]  # remove '.py'
            result = run_single_case(name, flags, opts.split(), arg.diff, arg.debug)
            print_test_result(name, result)
    else:
        try:
            testcases = glob.glob('t*' + arg.case + '*.py')
        except:
            print("cannot find testcase for : %s" % arg.case)
            sys.exit(1)
        for tc in sorted(testcases):
            name = tc[:-3]  # remove '.py'
            result = run_single_case(name, flags, opts.split(), arg.diff, arg.debug)
            print_test_result(name, result)
