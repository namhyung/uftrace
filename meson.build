# TODO: cross-compile supports is rudimentary

project('uftrace', 'c', version: '0.9.4')
python_module = import('python')

common_cflags = ['-D_GNU_SOURCE', '-D_DEFAULT_SOURCE', '-D_XOPEN_SOURCE=600']
common_cflags += '-fvisibility=hidden'
common_cflags += '-fno-omit-frame-pointer'
common_ldflags = []
uftrace_cflags    = ['-DINSTALL_LIB_PATH="@0@"'.format(get_option('prefix') / get_option('libdir'))]
libmcount_cflags  = []
demangler_cflags  = []
symbols_cflags    = []
dbginfo_cflags    = []
traceevent_cflags = []
test_cflags       = []

program_shell = find_program('sh', required: true)
program_git = find_program('git', required: true)

cc = meson.get_compiler('c')

host_machine_cpu_family = host_machine.cpu_family()
if host_machine_cpu_family == 'x86'
    host_machine_cpu_family = 'i386'
endif

if get_option('arch') == 'auto'
    arch = host_machine_cpu_family
elif get_option('arch') == host_machine_cpu_family
    arch = host_machine_cpu_family
else
    error('host compiler `@0@` doesn\'t match host architecture `@1@`'.format(
        host_machine_cpu_family, get_option('arch')))
endif

################################
# additional compilation flags #
################################

if get_option('debugging')
    common_cflags += ['-O0', '-g']
else
    common_cflags += ['-O2', '-g']
endif

if get_option('trace')
    trace_cflags       = ['-pg', '-fno-omit-frame-pointer']
    uftrace_cflags    += trace_cflags
    demangler_cflags  += trace_cflags
    symbols_cflags    += trace_cflags
    dbginfo_cflags    += trace_cflags
    traceevent_cflags += trace_cflags
    test_cflags       += trace_cflags
    # cannot add -pg to libmcount_cflags because mcount() is not reentrant
endif

if get_option('asan')
    asan_cflags = ['-O0', '-g', '-fsanitize=address,leak']
    common_ldflags   += ['-fsanitize=address,leak']

    uftrace_cflags    += asan_cflags
    demangler_cflags  += asan_cflags
    symbols_cflags    += asan_cflags
    dbginfo_cflags    += asan_cflags
    traceevent_cflags += asan_cflags
    test_cflags       += asan_cflags
endif

if get_option('coverage')
libmcount_cflags
    coverage_cflags   = ['-O0', '-g', '--coverage', '-U_FORTIFY_SOURCE']
    common_ldflags   += ['--coverage']
    common_cflags    += coverage_cflags
    libmcount_cflags += coverage_cflags
    test_cflags      += coverage_cflags
endif

if get_option('san') != ''
    if get_option('san') == 'all'
        sanitize_cflags = ['-O0', '-g', '-fsanitize=address,leak,undefined']
        common_ldflags += ['-fsanitize=address,leak,undefined']
    else
        sanitize_cflags = ['-O0', '-g', '-fsanitize=@0@'.format(get_option('sanitize'))]
        common_ldflags += ['-fsanitize=@0@'.format(get_option('sanitize'))]
    endif

    uftrace_cflags    += sanitize_cflags
    demangler_cflags  += sanitize_cflags
    symbols_cflags    += sanitize_cflags
    dbginfo_cflags    += sanitize_cflags
    traceevent_cflags += sanitize_cflags
    test_cflags       += sanitize_cflags
endif

################################
# -Dwith-capstone build option #
################################

libcapstone_is_enabled = false
libcapstone_dep = dependency('capstone', required: get_option('with-capstone'))
if libcapstone_dep.found()
    libcapstone_is_enabled = true
    common_cflags += '-DHAVE_LIBCAPSTONE'
endif

##############################
# -Dwith-libdw  build option #
# -Dwith-libelf build option #
##############################

libdw_is_enabled = false
libdw_dep = []

libelf_is_enabled = false
libelf_dep = dependency('libelf', required: get_option('with-libelf'))
if libelf_dep.found()
    libelf_is_enabled = true
    common_cflags += '-DHAVE_LIBELF'

    libdw_dep = dependency('libdw', required: get_option('with-libdw'))
    if libdw_dep.found()
        libdw_is_enabled = true
        common_cflags += '-DHAVE_LIBDW'
    endif
endif

#################################
# -Dwith-libluajit build option #
#################################

libluajit_is_enabled = false
libluajit_dep = dependency('luajit', required: get_option('with-libluajit'))
if libluajit_dep.found()
    libluajit_is_enabled =true
    common_cflags += '-DHAVE_LIBLUAJIT'
endif

##################################
# -Dwith-libncurses build option #
##################################

libncurses_is_enabled = false
libncurses_dep = dependency('ncurses', required: get_option('with-libncurses'))
if libncurses_dep.found()
    libncurses_is_enabled = true
    common_cflags += '-DHAVE_LIBNCURSES'
endif

#################################
# -Dwith-libpython build option #
#################################

libpython_is_enabled = false
libpython_dep = []
python2_installation = python_module.find_installation('python2', required: false)
python3_installation = python_module.find_installation('python3', required: false)
if python3_installation.found()
    libpython_dep = python3_installation.dependency()
    if libpython_dep.found()
        libpython_is_enabled = true
        common_cflags += '-DHAVE_LIBPYTHON3'
    endif
elif python2_installation.found()
    libpython_dep = python2_installation.dependency()
    if libpython_dep.found()
        libpython_is_enabled = true
        common_cflags += '-DHAVE_LIBPYTHON2'
    endif
endif

if get_option('with-libpython').enabled()
    if not libpython_is_enabled
        error('Failed to find a valid python installation')
    endif
endif

#################################
# -Dwith-libstdcxx build option #
#################################

cxa_demangle_is_enabled = false
cxa_demangle_dep = []
have_cxa_demangle_code = run_command('cat', files('check-deps/__cxa_demangle.c')).stdout().strip()
have_cxa_demangle_result = cc.run(have_cxa_demangle_code, name: 'cxa_demangle check', args: ['-lstdc++'])
if get_option('with-libstdcxx').auto()
    if have_cxa_demangle_result.returncode() == 0
        cxa_demangle_dep = cc.find_library('stdc++', required: true)
        cxa_demangle_is_enabled = true
        common_cflags += '-DHAVE_CXA_DEMANGLE'
        message('Enabling libstdc++')
    else
        message('Disabling libstdc++')
    endif
elif get_option('with-libstdcxx').enabled()
    if have_cxa_demangle_result.returncode() == 0
        cxa_demangle_dep = cc.find_library('stdc++', required: true)
        cxa_demangle_is_enabled = true
        common_cflags += '-DHAVE_CXA_DEMANGLE'
        message('Enabling libstdc++ (enabled by: with-libstdcxx)')
    else
        error('Failed to compile and run check-deps/__cxa_demangle.c')
    endif
else
    message('Disabling libstdc++ (enabled by: with-libstdcxx)')
endif

############################
# -Dwith-perf build option #
############################

perf_clockid_is_enabled = false
have_perf_clockid_code = run_command('cat', files('check-deps/__perf_clockid.c')).stdout().strip()
have_perf_clockid_result = cc.run(have_perf_clockid_code, name: 'perf clockid check')
if get_option('with-perf').auto()
    if have_perf_clockid_result.returncode() == 0
        perf_clockid_is_enabled = true
        common_cflags += '-DHAVE_PERF_CLOCKID'
        message('Enabling perf event support')
    else
        message('Disabling perf event support')
    endif
elif get_option('with-perf').enabled()
    if have_perf_clockid_result.returncode() == 0
        perf_clockid_is_enabled = true
        common_cflags += '-DHAVE_PERF_CLOCKID'
        message('Enabling perf event support (enabled by: with-perf)')
    else
        error('Failed to compile and run check-deps/__perf_clockid.c')
    endif
else
    message('Disabling perf event support (disabled by: with-perf)')
endif

################################
# -Dwith-schedule build option #
################################

perf_ctxsw_is_enabled = false
have_perf_ctxsw_code = run_command('cat', files('check-deps/__perf_context_switch.c')).stdout().strip()
have_perf_ctxsw_result = cc.run(have_perf_ctxsw_code, name: 'perf context switch check')
if get_option('with-schedule').auto()
    if have_perf_ctxsw_result.returncode() == 0
        perf_ctxsw_is_enabled = true
        common_cflags += '-DHAVE_PERF_CTXSW'
        message('Enabling scheduler event support')
    else
        message('Disabling scheduler event support')
    endif
elif get_option('with-schedule').enabled()
    if have_perf_clockid_result.returncode() == 0
        perf_clockid_is_enabled = true
        common_cflags += '-DHAVE_PERF_CLOCKID'
        message('Enabling scheduler event support (enabled by: with-schedule)')
    else
        error('Failed to compile and run check-deps/__perf_context_switch.c')
    endif
else
    message('Disabling scheduler event support (disabled by: with-schedule)')
endif

####################################
# -Dwith-libresolver build options #
####################################

# TODO: add -Dwith-libresolver option

libresolver_project = subproject('libresolver')
libresolver_dep = libresolver_project.get_variable('libresolver_dep')

#########################
# required dependencies #
#########################

libpthread_dep = cc.find_library('pthread', required: true)
libdl_dep = cc.find_library('dl', required: true)
librt_dep = cc.find_library('rt', required: true)

###########
# version #
###########

version_sh = find_program('misc/version.sh')
version_sh_cmd = '$(git describe --tags 2> /dev/null || echo v' + meson.project_version() + ')'
version_h = custom_target(
    'gen_version_h',
    output: 'version.h',
    command: [program_shell, '-c', version_sh.path() + ' @OUTPUT@' + ' ' + version_sh_cmd + ' @0@ .'.format(arch) + ' > /dev/null'],
)

#############################
# libmcount (arch specific) #
#############################

if arch == 'aarch64'
    libmcount_arch_include = include_directories('arch/aarch64')
    libmcount_arch_sources = [
        'arch/aarch64/cpuinfo.c',
        'arch/aarch64/mcount-dynamic.c',
        'arch/aarch64/mcount-insn.c',
        'arch/aarch64/mcount-support.c',
    ]
    libmcount_arch_asm_sources = [
        'arch/aarch64/dynamic.S',
        'arch/aarch64/mcount.S',
        'arch/aarch64/plthook.S',
    ]
    libmcount_arch_deps = []
elif arch == 'arm'
    libmcount_arch_include = include_directories('arch/arm')
    libmcount_arch_sources = [
        'arch/arm/cpuinfo.c',
        'arch/arm/mcount-support.c',
    ]
    libmcount_arch_asm_sources = [
        'arch/arm/mcount.S',
        'arch/arm/plthook.S',
    ]
    libmcount_arch_deps = []
elif arch == 'i386'
    libmcount_arch_include = include_directories('arch/i386')
    libmcount_arch_sources = [
        'arch/i386/cpuinfo.c',
        'arch/i386/mcount-dynamic.c',
        'arch/i386/mcount-support.c',
    ]
    libmcount_arch_asm_sources = [
        'arch/i386/common.S',
        'arch/i386/fentry.S',
        'arch/i386/mcount.S',
        'arch/i386/plthook.S',
    ]
    libmcount_arch_deps = []
elif arch == 'x86_64'
    libmcount_arch_include = include_directories('arch/x86_64')
    libmcount_arch_sources = [
        'arch/x86_64/cpuinfo.c',
        'arch/x86_64/mcount-dynamic.c',
        'arch/x86_64/mcount-event.c',
        'arch/x86_64/mcount-insn.c',
        'arch/x86_64/mcount-noplt.c',
        'arch/x86_64/mcount-support.c',
        'arch/x86_64/symbol.c',
    ]
    libmcount_arch_asm_sources = [
        'arch/x86_64/dynamic.S',
        'arch/x86_64/fentry.S',
        'arch/x86_64/mcount.S',
        'arch/x86_64/plthook.S',
        'arch/x86_64/xray.S',
    ]
    libmcount_arch_deps = [libresolver_dep]
else
    error('target architecture `@0@` is not supported'.format(arch))
endif

#############
# libmcount #
#############

libmcount_nop_sources = [
    'libmcount/mcount-nop.c',
]

libmcount_sources = [
    'libmcount/dynamic.c',
    'libmcount/event.c',
    'libmcount/mcount.c',
    'libmcount/misc.c',
    'libmcount/plthook.c',
    'libmcount/pmu.c',
    'libmcount/record.c',
    'libmcount/wrap.c',
    'utils/argspec.c',
    'utils/auto-args.c',
    'utils/debug.c',
    'utils/demangle.c',
    'utils/dwarf.c',
    'utils/filter.c',
    'utils/hashmap.c',
    'utils/rbtree.c',
    'utils/regs.c',
    'utils/script-luajit.c',
    'utils/script-python.c',
    'utils/script.c',
    'utils/symbol-libelf.c',
    'utils/symbol-rawelf.c',
    'utils/symbol.c',
    'utils/utils.c',
]

libmcount_base_deps = [
    cxa_demangle_dep,
    libcapstone_dep,
    libdl_dep,
    libdw_dep,
    libelf_dep,
    libluajit_dep,
    libmcount_arch_deps,
    libncurses_dep,
    libpthread_dep,
    libpython_dep,
    librt_dep,
]

libmcount = shared_library(
    'mcount', [libmcount_arch_sources, libmcount_arch_asm_sources, libmcount_sources, version_h],
    include_directories: [libmcount_arch_include],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags],
    link_args: [common_ldflags],
    install: true,
)

libmcount_fast = shared_library(
    'mcount-fast', [libmcount_arch_sources, libmcount_arch_asm_sources, libmcount_sources, version_h],
    include_directories: [libmcount_arch_include],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags, '-DDISABLE_MCOUNT_FILTER'],
    link_args: [common_ldflags],
    install: true,
)

libmcount_single = shared_library(
    'mcount-single', [libmcount_arch_sources, libmcount_arch_asm_sources, libmcount_sources, version_h],
    include_directories: [libmcount_arch_include],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags, '-DSINGLE_THREAD'],
    link_args: [common_ldflags],
    install: true,
)

libmcount_fast_single = shared_library(
    'mcount-fast-single', [libmcount_arch_sources, libmcount_arch_asm_sources, libmcount_sources, version_h],
    include_directories: [libmcount_arch_include],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags, '-DDISABLE_MCOUNT_FILTER', '-DSINGLE_THREAD'],
    link_args: [common_ldflags],
    install: true,
)

libmcount_fast_nop = shared_library(
    'mcount-nop', [libmcount_nop_sources, version_h],
    include_directories: [],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags, '-DDISABLE_MCOUNT_FILTER', '-DSINGLE_THREAD'],
    link_args: [common_ldflags],
    install: true,
)

#################
# libtraceevent #
#################

libtraceevent_include = include_directories('libtraceevent')

libtraceevent_sources = [
    'libtraceevent/event-parse.c',
    'libtraceevent/event-plugin.c',
    'libtraceevent/kbuffer-parse.c',
    'libtraceevent/parse-filter.c',
    'libtraceevent/parse-utils.c',
    'libtraceevent/trace-seq.c',
]

libtraceevent_other_includes = include_directories('libtraceevent/include')

libtraceevent = static_library(
    'traceevent', [libtraceevent_sources],
    include_directories: [libtraceevent_include, libtraceevent_other_includes],
    c_args: [common_cflags, traceevent_cflags],
    link_args: [common_ldflags],
    pic: true,
)

libtraceevent_dep = declare_dependency(
    include_directories: [libtraceevent_include],
    link_with: [libtraceevent],
)

###########
# uftrace #
###########

uftrace_include = include_directories('cmds')

uftrace_sources = [
    'arch/' + arch + '/cpuinfo.c',
    'cmds/dump.c',
    'cmds/graph.c',
    'cmds/info.c',
    'cmds/live.c',
    'cmds/record.c',
    'cmds/recv.c',
    'cmds/replay.c',
    'cmds/report.c',
    'cmds/script.c',
    'cmds/tui.c',
    'uftrace.c',
    'utils/argspec.c',
    'utils/auto-args.c',
    'utils/data-file.c',
    'utils/debug.c',
    'utils/demangle.c',
    'utils/dwarf.c',
    'utils/extern.c',
    'utils/field.c',
    'utils/filter.c',
    'utils/fstack.c',
    'utils/graph.c',
    'utils/hashmap.c',
    'utils/kernel.c',
    'utils/pager.c',
    'utils/perf.c',
    'utils/rbtree.c',
    'utils/regs.c',
    'utils/report.c',
    'utils/script-luajit.c',
    'utils/script-python.c',
    'utils/script.c',
    'utils/session.c',
    'utils/symbol-libelf.c',
    'utils/symbol-rawelf.c',
    'utils/symbol.c',
    'utils/utils.c',
]

uftrace_deps = [
    cxa_demangle_dep,
    libdl_dep,
    libdw_dep,
    libelf_dep,
    libluajit_dep,
    libncurses_dep,
    libpthread_dep,
    libpython_dep,
    librt_dep,
    libtraceevent_dep,
]

uftrace = executable(
    'uftrace', [uftrace_sources, version_h],
    include_directories: [uftrace_include],
    dependencies: [uftrace_deps],
    c_args: [common_cflags, uftrace_cflags],
    link_args: [common_ldflags],
    install: true,
)

###########
# dbginfo #
###########

dbginfo_sources = [
    'misc/dbginfo.c',
    'utils/argspec.c',
    'utils/auto-args.c',
    'utils/debug.c',
    'utils/demangle.c',
    'utils/dwarf.c',
    'utils/filter.c',
    'utils/rbtree.c',
    'utils/regs.c',
    'utils/symbol-libelf.c',
    'utils/symbol-rawelf.c',
    'utils/symbol.c',
    'utils/utils.c',
]

dbginfo_deps = [
    cxa_demangle_dep,
    libdl_dep,
    libdw_dep,
    libelf_dep,
]

dbginfo = executable(
    'dbginfo', [dbginfo_sources],
    dependencies: [dbginfo_deps],
    c_args: [common_cflags, dbginfo_cflags],
    link_args: [common_ldflags],
    build_by_default: true,
)

#############
# demangler #
#############

demangler_sources = [
    'misc/demangler.c',
    'utils/demangle.c',
    'utils/debug.c',
    'utils/utils.c',
]

demangler_deps = [
    cxa_demangle_dep,
]

demangler = executable(
    'demangler', [demangler_sources],
    dependencies: [demangler_deps],
    c_args: [common_cflags, demangler_cflags],
    link_args: [common_ldflags],
    build_by_default: true,
)

###########
# symbols #
###########

symbols_sources = [
    'misc/symbols.c',
    'utils/argspec.c',
    'utils/auto-args.c',
    'utils/debug.c',
    'utils/demangle.c',
    'utils/dwarf.c',
    'utils/filter.c',
    'utils/rbtree.c',
    'utils/regs.c',
    'utils/session.c',
    'utils/symbol-libelf.c',
    'utils/symbol-rawelf.c',
    'utils/symbol.c',
    'utils/utils.c',
]

symbols_deps = [
    cxa_demangle_dep,
    libdl_dep,
    libdw_dep,
    libelf_dep,
]

symbols = executable(
    'symbols', [symbols_sources],
    dependencies: [symbols_deps],
    c_args: [common_cflags, symbols_cflags],
    link_args: [common_ldflags],
    build_by_default: true,
)

#########
# tests #
#########

unittests_includes = include_directories('tests', 'arch/' + arch)

unittests_sources = [
    'cmds/dump.c',
    'cmds/graph.c',
    'cmds/info.c',
    'cmds/live.c',
    'cmds/record.c',
    'cmds/recv.c',
    'cmds/replay.c',
    'cmds/report.c',
    'cmds/script.c',
    'cmds/tui.c',
    'tests/unittest.c',
    'uftrace.c',
    'utils/argspec.c',
    'utils/auto-args.c',
    'utils/data-file.c',
    'utils/debug.c',
    'utils/demangle.c',
    'utils/dwarf.c',
    'utils/extern.c',
    'utils/field.c',
    'utils/filter.c',
    'utils/fstack.c',
    'utils/graph.c',
    'utils/hashmap.c',
    'utils/kernel.c',
    'utils/pager.c',
    'utils/perf.c',
    'utils/rbtree.c',
    'utils/regs.c',
    'utils/report.c',
    'utils/script-luajit.c',
    'utils/script-python.c',
    'utils/script.c',
    'utils/session.c',
    'utils/symbol-libelf.c',
    'utils/symbol-rawelf.c',
    'utils/symbol.c',
    'utils/utils.c',
    libmcount_arch_sources,
    libmcount_sources,
]

unittests_deps = [
    cxa_demangle_dep,
    libcapstone_dep,
    libdl_dep,
    libdw_dep,
    libelf_dep,
    libluajit_dep,
    libmcount_arch_deps,
    libncurses_dep,
    libpthread_dep,
    libpython_dep,
    librt_dep,
    libtraceevent_dep,
]

tests_dir = meson.source_root() + '/tests'

tests_unittest_h = tests_dir + '/unittest.h'

unittests = executable(
    'unittests', [unittests_sources],
    include_directories: [unittests_includes, libmcount_arch_include],
    dependencies: [unittests_deps],
    c_args: [common_cflags, test_cflags,  '-DUNIT_TEST', '-include', tests_unittest_h],
    link_args: [common_ldflags],
    build_by_default: false,
)

run_target('unittest',
    command: [unittests],
    depends: [unittests],
)

run_target('runtest',
    command: ['sh', '-c', 'cd @0@ && objdir=@1@ ./runtest.py'.format(tests_dir, meson.current_build_dir())],
    depends: [
        libmcount,
        libmcount_fast,
        libmcount_single,
        libmcount_fast_single,
        libmcount_fast_nop,
        uftrace,
    ],
)

run_target('tests',
    command: ['sh', '-c', 'cd @0@ && ninja unittest; ninja runtest'.format(meson.current_build_dir())],
)

#################
# documentation #
#################

doc_sources = [
    'uftrace-dump',
    'uftrace-graph',
    'uftrace-info',
    'uftrace-live',
    'uftrace-record',
    'uftrace-recv',
    'uftrace-replay',
    'uftrace-report',
    'uftrace-script',
    'uftrace-tui',
    'uftrace',
]

program_pandoc = find_program('pandoc', required: get_option('with-doc'))
if program_pandoc.found()
    foreach source_file : doc_sources
        if get_option('doc-lang') == 'en'
            markdown_file = files('doc/@0@.md'.format(source_file))
        elif get_option('doc-lang') == 'ko'
            markdown_file = files('doc/ko/@0@.md'.format(source_file))
        endif

        man_page = '@0@.1'.format(source_file)
        man_page_target = run_command('sh', '-c', 'printf @0@ | sed \'s/[-|\/]/_/g\''.format(man_page)).stdout().strip()

        custom_target(
            man_page_target,
            command: [program_pandoc, '-s', '@INPUT@', '-t', 'man', '-o', '@OUTPUT@'],
            input: markdown_file,
            output: man_page,
            install: true,
            install_dir: join_paths(get_option('mandir'), 'man1'),
        )
    endforeach
endif

#########
# ctags #
#########

ctags_command = ''
ctags_command += 'cd @0@ && '.format(meson.source_root())
ctags_command += 'find . -name "*\.[chS]" -o -path ./tests -prune -o -path ./check-deps -prune | '
ctags_command += 'xargs ctags --regex-asm=\'/^(GLOBAL|ENTRY|END)\(([^)]*)\).*/\2/\''

run_target('ctags',
    command: ['sh', '-c', ctags_command],
)

###########
# summary #
###########

color_green = '\u001b[32m'
color_red = '\u001b[31m'
color_off = '\u001b[0m'

text_on = color_green + 'on' + color_off + ' '
text_off = color_red + 'off' + color_off

libcapstone_is_enabled  = (libcapstone_is_enabled)  ? text_on : text_off
libdw_is_enabled        = (libdw_is_enabled)        ? text_on : text_off
libelf_is_enabled       = (libelf_is_enabled)       ? text_on : text_off
libluajit_is_enabled    = (libluajit_is_enabled)    ? text_on : text_off
libpython_is_enabled    = (libpython_is_enabled)    ? text_on : text_off
libncurses_is_enabled   = (libncurses_is_enabled)   ? text_on : text_off
cxa_demangle_is_enabled = (cxa_demangle_is_enabled) ? text_on : text_off
perf_clockid_is_enabled = (perf_clockid_is_enabled) ? text_on : text_off
perf_ctxsw_is_enabled   = (perf_ctxsw_is_enabled)   ? text_on : text_off

message('          prefix: @0@'.format(get_option('prefix')))
message('     libcapstone: [ @0@ ] - full dynamic tracing support'.format(libcapstone_is_enabled))
message('           libdw: [ @0@ ] - dwarf support'.format(libdw_is_enabled))
message('          libelf: [ @0@ ] - more flexible ELF data handling'.format(libelf_is_enabled))
message('       libluajit: [ @0@ ] - luajit scripting support'.format(libluajit_is_enabled))
message('       libpython: [ @0@ ] - python scripting support'.format(libpython_is_enabled))
message('      libncurses: [ @0@ ] - terminal UI support'.format(libncurses_is_enabled))
message('    cxa_demangle: [ @0@ ] - full demangler support with libstdc++'.format(cxa_demangle_is_enabled))
message('      perf event: [ @0@ ] - perf event support'.format(perf_clockid_is_enabled))
message('   perf schedule: [ @0@ ] - perf scheduler event support'.format(perf_ctxsw_is_enabled))
