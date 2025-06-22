#!/usr/bin/env python3

import glob
import multiprocessing
import os
import random
import re
import socket
import subprocess as sp
import sys
import tempfile
import time

class Elf:
    EI_NIDENT = 16

    @staticmethod
    def is_32bit(filename):
        # e_ident[] indexes
        EI_CLASS      = 4

        # EI_CLASS: ELFCLASSNONE, ELFCLASS32, ELFCLASS64, ELFCLASSNUM
        ELFCLASS32    = 1

        try:
            with open(filename, 'rb') as f:
                elf_ident = list(f.read(Elf.EI_NIDENT))
                ei_class = ord(elf_ident[EI_CLASS])

            if ei_class == ELFCLASS32:
                return True
        except Exception:
            pass

        return False

    @staticmethod
    def get_elf_machine(filename):
        # e_machine (architecture)
        EM_386        = 3       # Intel 80386
        EM_ARM        = 40      # ARM
        EM_X86_64     = 62      # AMD x86-64 architecture
        EM_AARCH64    = 183     # ARM AARCH64

        machine = {
            EM_386: 'i386',
            EM_ARM: 'arm',
            EM_X86_64: 'x86_64',
            EM_AARCH64: 'aarch64',
        }

        try:
            with open(filename, 'rb') as f:
                # consume elf_ident and e_type
                f.read(Elf.EI_NIDENT + 2)

                # read e_machine
                e_machine = f.read(2)[0]
                if isinstance(e_machine, str):
                    e_machine = ord(e_machine)

            return machine[e_machine]
        except Exception:
            pass

        return None

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

    origdir = os.getcwd()
    basedir = os.path.dirname(origdir)
    objdir = 'objdir' in os.environ and os.environ['objdir'] or basedir
    srcdir = 'srcdir' in os.environ and os.environ['srcdir'] or basedir
    uftrace_cmd = objdir + '/uftrace'
    default_opt = '--no-pager --no-event --libmcount-path=' + objdir

    default_cflags = ['-fno-inline', '-fno-builtin', '-fno-ipa-cp',
                      '-fno-omit-frame-pointer', '-D_FORTIFY_SOURCE=0']
    feature = set()

    def __init__(self, name, result, lang='C', cflags='', ldflags='', sort='task', serial=False):
        _tmp = tempfile.mkdtemp(prefix='test_%s_' % name)
        self.keep = False
        os.chdir(_tmp)
        self.test_dir = _tmp
        self.name = name
        self.result = result
        self.cflags = cflags
        self.ldflags = ldflags
        self.lang = lang
        self.sort_method = sort
        self.serial = serial
        self.subcmd = 'live'
        self.option = ''
        self.exearg = 't-' + name
        self.p_flag = ''
        self.p_libs = []
        self.test_feature()
        if Elf.get_elf_machine(self.uftrace_cmd) == 'i386':
            self.default_cflags.append('-m32')

    def set_compiler(self, compiler):
        if compiler == 'gcc':
            self.supported_lang['C']['cc'] = 'gcc'
            self.supported_lang['C++']['cc'] = 'g++'
        elif compiler == 'clang':
            self.supported_lang['C']['cc'] = 'clang'
            self.supported_lang['C++']['cc'] = 'clang++'
        else:
            # ignore invalid compiler argument
            pass

    def set_debug(self, dbg):
        self.debug = dbg

    def pr_debug(self, msg):
        if self.debug:
            print(msg)

    def set_keep(self, keep):
        self.keep = keep

    def gen_port(self, start = 40000, end = 50000):
        for port in random.sample(list(range(start, end + 1)), end - start + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("localhost", port))
                self.port = port
                return
            except OSError:
                pass
        raise Exception("No available port found")

    def test_feature(self):
        try:
            p = sp.Popen(self.uftrace_cmd + ' --version', shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
            uftrace_version = p.communicate()[0].decode(errors='ignore')
            s = uftrace_version.split()
            for i in range(3, len(s) - 1):
                self.feature.add(s[i])
            return True
        except Exception:
            return False

    def convert_abs_path(self, build_cmd):
        cmd = build_cmd.split()
        src_idx = [i for i, _cmd in enumerate(cmd) if _cmd.startswith('s-')][0]
        abs_src = os.path.join(self.basedir, 'tests', cmd[src_idx])
        cmd[src_idx] = abs_src
        return " ".join(cmd)

    def strip_tracing_flags(self, cmd):
        cmd = cmd.replace('-pg', '').replace('-finstrument-functions', '')
        cmd = re.sub(r'-fpatchable-function-entry=[0-9]+', '', cmd)
        return cmd

    def build_it(self, build_cmd):
        build_cmd = self.convert_abs_path(build_cmd)

        if '-fpatchable-function-entry' in build_cmd:
            self.p_flag = '-P .'
        try:
            p = sp.Popen(build_cmd.split(), stderr=sp.PIPE)
            if p.wait() != 0:
                self.pr_debug(p.communicate()[1].decode(errors='ignore'))
                return TestBase.TEST_BUILD_FAIL
            return TestBase.TEST_SUCCESS
        except OSError as e:
            self.pr_debug(e.strerror)
            return TestBase.TEST_BUILD_FAIL
        except Exception:
            return TestBase.TEST_BUILD_FAIL

    def build(self, name, cflags='', ldflags=''):
        if self.lang not in TestBase.supported_lang:
            self.pr_debug("%s: unsupported language: %s" % (name, self.lang))
            return TestBase.TEST_UNSUPP_LANG

        lang = TestBase.supported_lang[self.lang]
        prog = 't-' + name
        src  = 's-' + name + lang['ext']

        build_cflags  = ' '.join(TestBase.default_cflags + [self.cflags, cflags, \
                                  os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, os.getenv('LDFLAGS', '')])

        build_cmd = '%s -o %s %s %s %s' % (lang['cc'], prog, build_cflags, src, build_ldflags)

        self.pr_debug("build command: %s" % build_cmd)
        return self.build_it(build_cmd)

    def build_notrace_lib(self, dstname, srcname, cflags='', ldflags =''):
        lang = TestBase.supported_lang['C']

        build_cflags  = ' '.join(TestBase.default_cflags + [self.cflags, cflags, \
                                  os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, os.getenv('LDFLAGS', '')])

        lib_cflags = build_cflags + ' -shared -fPIC'

        build_cmd = '%s -o lib%s.so %s s-%s.c %s' % \
                    (lang['cc'], dstname, lib_cflags, srcname, build_ldflags)

        build_cmd = self.strip_tracing_flags(build_cmd)
        self.pr_debug("build command for library: %s" % build_cmd)
        return self.build_it(build_cmd)

    def build_libabc(self, cflags='', ldflags=''):
        lang = TestBase.supported_lang['C']

        build_cflags  = ' '.join(TestBase.default_cflags + [self.cflags, cflags, \
                                  os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, os.getenv('LDFLAGS', '')])

        lib_cflags = build_cflags + ' -shared -fPIC'

        if '-fpatchable-function-entry' in cflags:
            self.p_libs.append('libabc_test_lib.so')

        # build libabc_test_lib.so library
        build_cmd = '%s -o libabc_test_lib.so %s s-lib.c %s' % (lang['cc'], lib_cflags, build_ldflags)

        self.pr_debug("build command for library: %s" % build_cmd)
        return self.build_it(build_cmd)

    def build_libfoo(self, name, cflags='', ldflags=''):
        lang = TestBase.supported_lang['C++']

        build_cflags  = ' '.join(TestBase.default_cflags + [self.cflags, cflags, \
                                  os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, os.getenv('LDFLAGS', '')])

        lib_cflags = build_cflags + ' -shared -fPIC'

        if '-fpatchable-function-entry' in cflags:
            self.p_libs.append('lib%s.so' % name)

        # build lib{foo}.so library
        build_cmd = '%s -o lib%s.so %s s-lib%s%s %s' % \
                    (lang['cc'], name, lib_cflags, name, lang['ext'], build_ldflags)

        self.pr_debug("build command for library: %s" % build_cmd)
        return self.build_it(build_cmd)

    def build_libmain(self, exename, srcname, libs, cflags='', ldflags='', instrument=True):
        if self.lang not in TestBase.supported_lang:
            self.pr_debug("%s: unsupported language: %s" % (self.name, self.lang))
            return TestBase.TEST_UNSUPP_LANG

        lang = TestBase.supported_lang[self.lang]
        prog = 't-' + exename
        build_cflags  = ' '.join(TestBase.default_cflags +
                                 [self.cflags, cflags, os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, os.getenv('LDFLAGS', '')])
        exe_ldflags = build_ldflags + ' -Wl,-rpath,$ORIGIN -L. '

        if '-fpatchable-function-entry' in cflags:
            self.p_libs.append(prog)

        for lib in libs:
            exe_ldflags += ' -l' + lib[3:-3]

        build_cmd = '%s -o %s %s %s %s' % (lang['cc'], prog, build_cflags, srcname, exe_ldflags)
        if not instrument:
            build_cmd = self.strip_tracing_flags(build_cmd)

        self.pr_debug("build command for executable: %s" % build_cmd)
        return self.build_it(build_cmd)

    def prepare(self):
        """ This function returns command line need to be run before"""
        return ''

    def setup(self):
        """ This function sets up options to be passed to runcmd"""
        pass

    def runcmd(self):
        """ This function returns (shell) command that runs the test.
            A test case can extend this to setup a complex configuration.  """

        if len(self.p_libs) > 0:
            self.p_flag = ''
            for lib in self.p_libs:
                self.p_flag += '-P .@%s ' % lib

        if '-P' in self.option:
            self.p_flag = ''

        # On aarch64, gcc and clang emit calls to memcpy() to pass and return structs.
        # This depends on a number of factors (gcc, clang, size and optimisation levels).
        # For now, it affects all tests tracing s-arg.c:pass() and return.c:return_large().
        # Any test can be affected by it and it may change from compiler to compiler.
        # To prevent inconsistencies, filter all calls to memcpy() for all tests:
        self.option += ' -N memcpy'

        return '%s %s %s %s %s %s' % (TestBase.uftrace_cmd, self.subcmd, \
                                   TestBase.default_opt, self.p_flag, self.option, self.exearg)

    def task_sort(self, output, ignore_children=False):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        pids = {}
        order = 1
        before_main = True
        for ln in output.split('\n'):
            if ln.find(' | main()') > 0 or ln.find(' | __main__.<module>') > 0:
                before_main = False
            if before_main:
                continue
            # ignore result of remaining functions which follows a blank line
            if ln.strip() == '':
                break
            pid_patt = re.compile(r'[^[]+\[ *(\d+)\] |')
            m = pid_patt.match(ln)
            try:
                pid = int(m.group(1))
            except Exception:
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
                    result += '\n'.join(pids[p]['result']) + '\n'
                result = result.strip()
        except Exception:
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
            try:
                if line[-1].startswith('__'):
                    continue
            except Exception:
                pass
            result.append('%s %s' % (line[-2], line[-1]))

        return '\n'.join(result)

    def graph_sort(self, output, ignored):
        """ This function post-processes output of the test to be compared.
            It ignores blank and comment (#) lines and header lines.  """
        result = []
        mode = 0
        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#'):
                continue
            # A graph result consists of backtrace and calling functions
            if ln.startswith('=============== BACKTRACE ==============='):
                mode = 1
                continue
            if ln.startswith('========== FUNCTION CALL GRAPH =========='):
                mode = 2
                continue
            if mode == 1:
                if ln.startswith(' backtrace #'):
                    result.append(ln.split(',')[0])  # remove time part
                if ln.startswith('   ['):
                    result.append(ln.split('(')[0])  # remove '(addr)' part
            if mode == 2:
                if " : " in ln:
                    result.append(ln.split(':')[1])  # remove time part
                else:
                    result.append(ln)

        return '\n'.join(result)

    def dump_sort(self, output, ignored):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []

        # A (raw) dump result consists of following data
        # <timestamp> <tid>: [<type>] <func>(<addr>) depth: <N>
        patt = re.compile(r'[^[]*(?P<type>\[(entry|exit )\]) (?P<func>[_a-z0-9]*)\([0-9a-f]+\) (?P<depth>.*)')

        # A (raw) dump argument patter
        arg_patt = re.compile(r'^  args')

        for ln in output.split('\n'):
            if ln.startswith('uftrace'):
                #result.append(ln)
                pass
            else:
                m = arg_patt.match(ln)
                if m is not None:
                    result.append(ln)
                    continue

                m = patt.match(ln)
                if m is None:
                    continue
                # ignore __monstartup and __cxa_atexit
                if m.group('func').startswith('__'):
                    continue
                result.append(patt.sub(r'\g<type> \g<depth> \g<func>', ln))

        return '\n'.join(result)

    def chrome_sort(self, output, ignored):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        import json

        # A chrome dump results consists of following JSON object:
        # {"ts": <timestamp>, "ph": <type>, "pid": <number>, "name": <func>}
        result = []
        try:
            o = json.loads(output)
        except Exception:
            return ''
        for ln in o['traceEvents']:
            if ln['ph'] == "M":
                if ln['name'] == "process_name" or ln['name'] == "thread_name":
                    args = ln['args']
                    name = args['name']
                    m = re.search(r'\[\d+\] (.*)', args['name'])
                    if m:
                        name = m.group(1)
                    result.append("%s %s %s" % (ln['ph'], ln['name'], name))
            else:
                result.append("%s %s" % (ln['ph'], ln['name']))
        return '\n'.join(result)

    def mermaid_sort(self, output, ignore_children=False):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        start_mermaid = False

        for ln in output.split('\n'):
            if ln.find('<div class=\"mermaid\"') >= 0:
                start_mermaid = True
                continue
            if start_mermaid == False:
                continue
            if ln.find('</div>') >= 0:
                break

            m = re.match( r'\s+(?P<start_depth>\d+)_(?P<start_id>\d+)\[\"(?P<start_name>\S+)\"\]\s+'
                + r'-->\|(?P<call_num>\d+)\|\s+(?P<end_depth>\d+)_(?P<end_id>\d+)\[\"(?P<end_name>\S+)\"\];', ln)
            if m:
                result.append("%s_%s_%s %s> %s_%s_%s" % (m.group('start_depth'), m.group('start_id'), m.group('start_name'),
                m.group('call_num'), m.group('end_depth'), m.group('end_id'), m.group('end_name')))
            else:
                continue
        return '\n'.join(result)

    def sort(self, output, ignore_children=False):
        if not hasattr(TestBase, self.sort_method + '_sort'):
            print('cannot find the sort function: %s' % self.sort_method)
            return ''  # this leads to a failure with 'NG'
        func = TestBase.__dict__[self.sort_method + '_sort']
        if callable(func):
            return func(self, output, ignore_children)
        else:
            return ''  # this leads to a failure with 'NG'

    def postrun(self, result):
        """This function is called after running a testcase"""
        return result

    def fixup(self, cflags, result):
        """This function is called when result is different to expected.
           But if we know some known difference on some optimization level,
           apply it and re-test with the modified result."""
        return result

    def check_dependency(self, item):
        import os.path
        return os.path.exists('%s/check-deps/' % self.basedir + item)

    def check_perf_paranoid(self):
        if not 'perf' in TestBase.feature:
            return False
        try:
            f = open('/proc/sys/kernel/perf_event_paranoid')
            v = int(f.readline())
            f.close()

            if v >= 3:
                return False
        except Exception:
            pass

        return True

    def is_32bit(self):
        return Elf.is_32bit('t-' + self.name)

    def get_machine(self):
        return os.uname()[4]

    def get_elf_machine(self):
        return Elf.get_elf_machine('t-' + self.name)

    def check_arch_full_dynamic_support(self):
        elf_machine = TestBase.get_elf_machine(self)
        if elf_machine == 'x86_64' or elf_machine == 'aarch64':
            return True
        return False

    def check_arch_mfentry_mnop_mcount_support(self):
        machine = TestBase.get_machine(self)
        if machine == 'x86_64' or machine == 'i386':
            return True
        return False

    def check_arch_sdt_support(self):
        machine = TestBase.get_machine(self)
        if machine == 'x86_64':
            return True
        return False

    def prerun(self, timeout):
        self.subcmd = 'live'
        self.option = ''
        self.exearg = 't-' + self.name
        if self.lang == 'Python':
            self.exearg = TestBase.srcdir + '/tests/' + 's-' + self.name + '.py'

        cmd = self.prepare()
        if cmd == '':
            return TestBase.TEST_SUCCESS

        self.pr_debug("prerun command: " + cmd)

        class Timeout(Exception):
            pass

        def timeout_handler(sig, frame):
            raise Timeout

        ret = TestBase.TEST_SUCCESS
        import signal
        signal.signal(signal.SIGALRM, timeout_handler)

        try:
            signal.alarm(timeout)
            sp.call(cmd.split())
        except Timeout:
            ret = TestBase.TEST_TIME_OUT
        signal.alarm(0)

        return ret

    def run(self, name, cflags, diff, timeout):
        ret = TestBase.TEST_SUCCESS
        dif = ''

        self.setup()
        test_cmd = self.runcmd()
        self.pr_debug("test command: %s" % test_cmd)

        if self.debug:
            # In verbose mode, stderr is printed as is without redirection.
            # This will inform error messages to users when something goes wrong.
            p = sp.Popen(test_cmd, shell=True, stdout=sp.PIPE)
        else:
            p = sp.Popen(test_cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)

        class Timeout(Exception):
            pass

        def timeout_handler(sig, frame):
            try:
                p.kill()
            finally:
                raise Timeout

        import signal
        signal.signal(signal.SIGALRM, timeout_handler)

        timed_out = False
        try:
            signal.alarm(timeout)
            result_origin = p.communicate()[0].decode(errors='ignore')
        except Timeout:
            result_origin = ''
            timed_out = True
        signal.alarm(0)

        try:
            result_tested = self.sort(result_origin)  # for python3, may fail!
            result_expect = self.sort(self.result)
        except IndexError:
            result_tested = result_origin
            result_expect = self.result

        # strip trailing whitespace for each line.
        result_expect = '\n'.join([line.rstrip() for line in result_expect.split('\n')])
        result_tested = '\n'.join([line.rstrip() for line in result_tested.split('\n')])

        ret = p.wait()
        if ret < 0:
            if timed_out:
                return TestBase.TEST_TIME_OUT, ''
            else:
                return TestBase.TEST_ABNORMAL_EXIT, ''
        if ret > 0:
            if ret == 2:
                return TestBase.TEST_ABNORMAL_EXIT, ''
            if diff:
                compiler = self.supported_lang[self.lang]['cc']
                dif = "%s: %s %s returns %d\n" % (name, compiler, cflags, ret)
            return TestBase.TEST_NONZERO_RETURN, dif

        self.pr_debug("=========== %s ===========\n%s" % ("original", result_origin))
        self.pr_debug("=========== %s ===========\n%s" % (" result ", result_tested))
        self.pr_debug("=========== %s ===========\n%s" % ("expected", result_expect))

        if result_expect.strip() == '':
            if diff:
                dif = "%s: has no output for %s\n" % (name, cflags)
            return TestBase.TEST_DIFF_RESULT, dif

        if result_expect != result_tested:
            try:
                result_expect = self.sort(self.fixup(cflags, self.result))
                ret = TestBase.TEST_SUCCESS_FIXED
            except IndexError:
                return TestBase.TEST_DIFF_RESULT, "Internal error: Expected more results"

        if result_expect != result_tested:
            if diff:
                f = open('expect', 'w')
                f.write(result_expect + '\n')
                f.close()
                f = open('result', 'w')
                f.write(result_tested + '\n')
                f.close()

                compiler = self.supported_lang[self.lang]['cc']
                dif = "%s: diff result of %s %s\n" % (name, compiler, cflags)
                try:
                    p = sp.Popen(['colordiff', '-U1', 'expect', 'result'], stdout=sp.PIPE)
                except Exception:
                    p = sp.Popen(['diff', '-U1', 'expect', 'result'], stdout=sp.PIPE)
                dif += p.communicate()[0].decode(errors='ignore')
                os.remove('expect')
                os.remove('result')
            return TestBase.TEST_DIFF_RESULT, dif

        return ret, ''

    def __del__(self):
        if self.keep:
            sp.call(['mv', self.test_dir, TestBase.origdir])
        else:
            sp.call(['rm', '-rf', self.test_dir])

class PyTestBase(TestBase):
    def __init__(self, name, result, lang='Python', cflags='', ldflags='', sort='simple', serial=False):
        TestBase.__init__(self, name, result, lang, cflags, ldflags, sort, serial)
        # setup PYTHONPATH to load the new code before the inst
        orig_path = os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else ""
        os.environ["PYTHONPATH"] = TestBase.objdir + '/python'
        if TestBase.objdir != TestBase.srcdir:
            os.environ["PYTHONPATH"] += ':' + TestBase.objdir + '/python'
        if orig_path != "":
            os.environ["PYTHONPATH"] += ':' + orig_path

RED     = '\033[1;31m'
GREEN   = '\033[1;32m'
YELLOW  = '\033[1;33m'
NORMAL  = '\033[0m'

colored_result = {
    TestBase.TEST_SUCCESS:        GREEN  + 'OK' + NORMAL,
    TestBase.TEST_UNSUPP_LANG:    YELLOW + 'LA' + NORMAL,
    TestBase.TEST_BUILD_FAIL:     YELLOW + 'BI' + NORMAL,
    TestBase.TEST_ABNORMAL_EXIT:  RED    + 'SG' + NORMAL,
    TestBase.TEST_TIME_OUT:       RED    + 'TM' + NORMAL,
    TestBase.TEST_DIFF_RESULT:    RED    + 'NG' + NORMAL,
    TestBase.TEST_NONZERO_RETURN: RED    + 'NZ' + NORMAL,
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
    TestBase.TEST_SUCCESS:        'Test succeeded',
    TestBase.TEST_UNSUPP_LANG:    'Unsupported Language',
    TestBase.TEST_BUILD_FAIL:     'Build failed',
    TestBase.TEST_ABNORMAL_EXIT:  'Abnormal exit by signal',
    TestBase.TEST_TIME_OUT:       'Test ran too long',
    TestBase.TEST_DIFF_RESULT:    'Different test result',
    TestBase.TEST_NONZERO_RETURN: 'Non-zero return value',
    TestBase.TEST_SKIP:           'Skipped',
    TestBase.TEST_SUCCESS_FIXED:  'Test succeeded (with some fixup)',
}


def check_serial_case(case):
    # for python3
    _locals = {}
    exec("import %s; tc = %s.TestCase()" % (case, case), globals(), _locals)
    tc = _locals['tc']
    return tc.serial


def run_python_case(T, case, timeout):
    tc = T.TestCase()
    tc.set_debug(arg.debug)
    tc.set_keep(arg.keep)

    # to load uftrace.py and uftrace_python.so module
    sys.path.append(TestBase.objdir + '/python')
    sys.path.append(TestBase.srcdir + '/python')

    ret = tc.prerun(timeout)
    dif = ''
    if ret == TestBase.TEST_SUCCESS:
        ret, dif = tc.run(case, "", arg.diff, timeout)
        ret = tc.postrun(ret)
    return (ret, dif)

def run_single_case(case, flags, opts, arg, compilers):
    result = []
    timeout = int(arg.timeout)

    if timeout == -1:
        # kernel tests takes more time to setup
        if 'kernel' in case:
            timeout = 30
        else:
            timeout = 5

    # for python3
    _locals = {}
    exec("import %s as T" % (case), globals(), _locals)
    T = _locals['T']

    for compiler in compilers:
        if compiler == 'python':
            ret, dif = run_python_case(T, case, timeout)
            result.append((ret, dif))
            continue

        for flag in flags:
            for opt in opts:
                tc = T.TestCase()
                tc.set_debug(arg.debug)
                tc.set_keep(arg.keep)
                tc.set_compiler(compiler)

                cflags = ' '.join(["-" + flag, "-" + opt, tc.cflags])
                # add -fno-ipa-sra to prevent function renames like foo.isra.0
                # this is available on GCC only
                if compiler == 'gcc':
                    cflags += ' -fno-ipa-sra'

                dif = ''
                ret = tc.build(tc.name, cflags)
                if ret == TestBase.TEST_SUCCESS:
                    ret = tc.prerun(timeout)
                    if ret == TestBase.TEST_SUCCESS:
                        ret, dif = tc.run(case, cflags, arg.diff, timeout)
                        ret = tc.postrun(ret)
                result.append((ret, dif))

    return result


def save_test_result(result, case, shared):
    # save diff before results for print_test_result() to see it
    shared.diffs[case]   = [r[1] for r in result]
    shared.results[case] = [r[0] for r in result]
    shared.progress += 1
    for r in result:
        shared.stats[r[0]] += 1
        shared.total += 1


def print_test_result(case, result, diffs, color, ftests, nr_compilers):
    plain_result = [text_result[r] for r in result]

    if color:
        result_list = [colored_result[r] for r in result]
    else:
        result_list = plain_result

    for dif in diffs:
        if dif != '':
            sys.stdout.write(dif + '\n')

    output = case[1:4]
    output += ' %-20s' % case[5:] + ':'
    result_per_compiler = len(result_list) // nr_compilers
    for i in range(nr_compilers):
        output += ' '
        if i != 0:
            output += ' '
        begin = result_per_compiler * i
        end = result_per_compiler * (i + 1)
        output += ' '.join(result_list[begin:end])
    output += '\n'

    # write abnormal test result to failed-tests.txt
    normal = [TestBase.TEST_SUCCESS, TestBase.TEST_SUCCESS_FIXED, TestBase.TEST_SKIP]
    for r in result:
        if r not in normal:
            ftests.write(output)
            ftests.flush()
            break

    if arg.quiet:
        for r in result:
            if r not in normal:
                sys.stdout.write(output)
                break
    else:
        sys.stdout.write(output)


def print_test_header(opts, flags, ftests, compilers):
    optslen = len(opts)
    header1 = '%-24s ' % 'Compiler'
    header2 = '%-24s ' % 'Runtime test case'
    header3 = '-' * 24 + ':'
    empty = ' ' * 100

    for i, compiler in enumerate(compilers):
        if i != 0:
            header1 += ' '
            header2 += ' '
            header3 += ' '
        for flag in flags:
            # align with optimization flags
            header2 += ' ' + flag[:optslen] + empty[len(flag):optslen]
            header3 += ' ' + opts
        header1 += ' ' + compiler[:optslen*len(flags)+len(flags)-1] + empty[len(compiler):len(header3)-len(header1)-1]

    print("")
    print(header1)
    print(header2)
    print(header3)
    ftests.write(header1 + '\n')
    ftests.write(header2 + '\n')
    ftests.write(header3 + '\n')
    ftests.flush()


def print_python_test_header(ftests):
    header1 = '%-24s  %s' % ('Python test case', 'Result')
    header2 = '-' * 32

    print("")
    print(header1)
    print(header2)
    ftests.write(header1 + '\n')
    ftests.write(header2 + '\n')
    ftests.flush()


def print_test_report(color, shared):
    success = shared.stats[TestBase.TEST_SUCCESS] + shared.stats[TestBase.TEST_SUCCESS_FIXED]
    percent = 100.0 * success / shared.total

    print("")
    print("runtime test stats")
    print("====================")
    print("total %5d  Tests executed (success: %.2f%%)" % (shared.total, percent))
    for r in res:
        if color:
            result = colored_result[r]
        else:
            result = text_result[r]
        print("  %s: %5d  %s" % (result, shared.stats[r], result_string[r]))


def parse_argument():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--profile-flags", dest='flags',
                        default="pg finstrument-functions fpatchable-function-entry",
                        help="comma separated list of compiler profiling flags")
    parser.add_argument("-O", "--optimize-levels", dest='opts', default="0123s",
                        help="compiler optimization levels")
    parser.add_argument("cases", nargs='?', default="all",
                        help="test cases: 'all' or test number or (partial) name")
    parser.add_argument("-p", "--profile-pg", dest='pg_flag', action='store_true',
                        help="profiling with -pg option")
    parser.add_argument("-i", "--instrument-functions", dest='if_flag', action='store_true',
                        help="profiling with -finstrument-functions option")
    parser.add_argument("-e", "--patchable-function-entry", dest='pfe_flag', action='store_true',
                        help="profiling with -fpatchable-function-entry option")
    parser.add_argument("-d", "--diff", dest='diff', action='store_true',
                        help="show diff result if not matched")
    parser.add_argument("-v", "--verbose", dest='debug', action='store_true',
                        help="show internal command and result for debugging")
    parser.add_argument("-l", "--color", dest='color', default='auto',
                        help="set color in the output. 'auto', 'on' or 'off'")
    parser.add_argument("-t", "--timeout", dest='timeout', default="-1",
                        help="fail test if it runs more than TIMEOUT seconds")
    parser.add_argument("-j", "--worker", dest='worker', type=int, default=multiprocessing.cpu_count(),
                        help="Parallel worker count; using all core for default")
    parser.add_argument("-c", "--compiler", dest='compiler', default="all",
                        help="Select compiler gcc or clang. (use both by default)")
    parser.add_argument("-k", "--keep", dest='keep', action='store_true',
                        help="keep the test directories with compiled binaries")
    parser.add_argument("-q", "--quiet", dest='quiet', action='store_true',
                        help="Hide normal results and print only abnormal results.")
    parser.add_argument("-P", "--python", dest='python', action='store_true',
                        help="Run python test cases instead")

    return parser.parse_args()


if __name__ == "__main__":
    # prevent to create .pyc files (it makes some tests failed)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

    arg = parse_argument()

    testcases = []
    if arg.cases == 'all':
        if arg.python:
            testcases = glob.glob('p???_*.py')
        else:
            testcases = glob.glob('t???_*.py')
    else:
        try:
            cases = arg.cases.split('|')
            for case in cases:
                if arg.python:
                    testcases.extend(glob.glob('p*' + case + '*.py'))
                else:
                    testcases.extend(glob.glob('t*' + case + '*.py'))
            arg.worker = min(arg.worker, len(testcases))
        finally:
            if len(testcases) == 0:
                print("cannot find testcase for : %s" % arg.cases)
                sys.exit(0)

    # Use multiprocessing pool if the number of workers is greater than 1.
    use_pool = arg.worker > 1

    opts = ' '.join(sorted(['O' + o for o in arg.opts]))

    patch_size = {
        'x86_64'  : 5,
        'aarch64' : 2,
    }

    m = os.uname()[-1]  # machine

    if arg.pg_flag:
        flags = ['pg']
    elif arg.if_flag:
        flags = ['finstrument-functions']
    elif arg.pfe_flag:
        flags = ['fpatchable-function-entry']
        if m not in patch_size:
            print('fpatchable-function-entry not supported on current platform\n')
            exit(-1)
    else:
        flags = arg.flags.split()
        if m not in patch_size:
            flags.remove('fpatchable-function-entry')

    for i in range(len(flags)):
        if flags[i] == 'fpatchable-function-entry':
            flags[i] += '=%d' % patch_size[m]

    def has_compiler(compiler):
        installed = os.system('command -v %s > /dev/null' % compiler) == 0
        return installed

    compilers = []
    if arg.python:
        compilers.append('python')
    elif arg.compiler == 'all':
        for compiler in ['gcc', 'clang']:
            if has_compiler(compiler):
                compilers.append(compiler)
    else:
        if has_compiler(arg.compiler):
            compilers.append(arg.compiler)
    nr_compilers = len(compilers)
    if nr_compilers == 0:
        print('no compilers available for testing\n')
        sys.exit(-1)

    from functools import partial
    class dotdict(dict):
        """dot.notation access to dictionary attributes"""
        __getattr__ = dict.get
        __setattr__ = dict.__setitem__
        __delattr__ = dict.__delitem__

    manager = multiprocessing.Manager() if use_pool else None
    shared = manager.dict() if use_pool else dotdict()

    shared.tests_count = len(testcases)
    shared.progress = 0
    shared.results = dict()
    shared.diffs = dict()
    shared.total = 0
    res = []
    res.append(TestBase.TEST_SUCCESS)
    res.append(TestBase.TEST_SUCCESS_FIXED)
    res.append(TestBase.TEST_DIFF_RESULT)
    res.append(TestBase.TEST_NONZERO_RETURN)
    res.append(TestBase.TEST_ABNORMAL_EXIT)
    res.append(TestBase.TEST_TIME_OUT)
    res.append(TestBase.TEST_BUILD_FAIL)
    res.append(TestBase.TEST_UNSUPP_LANG)
    res.append(TestBase.TEST_SKIP)

    failed_tests = "failed-tests.txt"
    if os.path.exists(failed_tests):
        os.rename(failed_tests, failed_tests + ".old")
    ftests = open(failed_tests, "w")

    shared.stats = dict.fromkeys(res, 0)
    pool = multiprocessing.Pool(arg.worker) if use_pool else None
    serial_pool = multiprocessing.Pool(1) if use_pool else None

    if use_pool:
        print("Start %s tests with %d worker" % (shared.tests_count, arg.worker))
    else:
        print("Start %s tests without worker pool" % shared.tests_count)

    if arg.python:
        print_python_test_header(ftests)
    else:
        print_test_header(opts, flags, ftests, compilers)

    color = True
    if arg.color == 'auto':
        if not sys.stdout.isatty():
            color = False
        if 'TERM' in os.environ and os.environ['TERM'] == 'dumb':
            color = False
    elif arg.color == 'on':
        color = True
    elif arg.color == 'off':
        color = False
    else:
        print("unknown color: %s" % arg.color)
        sys.exit(-1)

    for tc in sorted(testcases):
        name = tc.split('.')[0]  # remove '.py'
        if use_pool:
            _pool = serial_pool if check_serial_case(name) else pool
            clbk = partial(save_test_result, case=name, shared=shared)

            _pool.apply_async(run_single_case, callback=clbk,
                            args=[name, flags, opts.split(), arg, compilers])
        else:
            results = run_single_case(name, flags, opts.split(), arg, compilers)
            save_test_result(results, case=name, shared=shared)

            # Print sequentially when executing in serial
            print_test_result(name, shared.results[name], shared.diffs[name], color, ftests, nr_compilers)

    if use_pool:
        # Print via polling when using multiprocessing pool
        for tc in sorted(testcases):
            name = tc.split('.')[0]  # remove '.py'

            while name not in shared.results:
                time.sleep(1)

            print_test_result(name, shared.results[name], shared.diffs[name], color, ftests, nr_compilers)

    if use_pool:
        pool.close()
        pool.join()

    ftests.close()

    sys.stdout.write("\n")
    sys.stdout.flush()

    if shared.progress >= 10 or shared.total >= 300:
        print_test_report(color, shared)
