project('uftrace', 'c', version: '0.10')
python_module = import('python')

common_cflags = ['-D_GNU_SOURCE', '-D_DEFAULT_SOURCE', '-D_XOPEN_SOURCE=600']
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

###################
# cross-compiling #
###################

cross_compiling = build_machine.cpu_family() != host_machine.cpu_family()
if cross_compiling
    warning('cross-compiling uftrace is experimental, please report any bugs to the issue tracker')
endif

host_machine_cpu_family = host_machine.cpu_family()
if host_machine_cpu_family == 'x86'
    arch = 'i386'
else
    arch = host_machine_cpu_family
endif

################################
# additional compilation flags #
################################

if get_option('debug')
    common_cflags += ['-DDEBUG_MODE=1']
else
    common_cflags += ['-DDEBUG_MODE=0']
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

if get_option('coverage')
    coverage_cflags   = ['-O0', '-g', '--coverage', '-U_FORTIFY_SOURCE']
    common_ldflags   += ['--coverage']
    common_cflags    += coverage_cflags
    libmcount_cflags += coverage_cflags
    test_cflags      += coverage_cflags
endif

################################
# -Dwith-capstone build option #
################################

libcapstone_dep = dependency('capstone', required: get_option('with-capstone'))
libcapstone_is_enabled = libcapstone_dep.found()
if libcapstone_is_enabled
    common_cflags += '-DHAVE_LIBCAPSTONE'
endif

##############################
# -Dwith-libdw  build option #
# -Dwith-libelf build option #
##############################

libelf_dep = dependency('libelf', required: get_option('with-libelf'))
libelf_is_enabled = libelf_dep.found()
if libelf_is_enabled
    common_cflags += '-DHAVE_LIBELF'

    libdw_dep = dependency('libdw', required: get_option('with-libdw'))
    libdw_is_enabled = libdw_dep.found()
    if libdw_is_enabled
        common_cflags += '-DHAVE_LIBDW'
    endif
else
    libdw_dep = []
    libdw_is_enabled = false
endif

#################################
# -Dwith-libluajit build option #
#################################

libluajit_dep = dependency('luajit', required: get_option('with-libluajit'))
libluajit_is_enabled = libluajit_dep.found()
if libluajit_is_enabled
    common_cflags += '-DHAVE_LIBLUAJIT'
endif

###################################
# -Dwith-libncursesw build option #
###################################

libncursesw_dep = dependency('ncursesw', required: get_option('with-libncursesw'))
libncursesw_is_enabled = libncursesw_dep.found()
if libncursesw_is_enabled
    common_cflags += '-DHAVE_LIBNCURSES'
endif

#################################
# -Dwith-libpython build option #
#################################

python_installation = python_module.find_installation('python', required: get_option('with-libpython'))
libpython_dep = []
libpython_is_enabled = python_installation.found()
if libpython_is_enabled
    libpython_dep = python_installation.dependency()
    python_version = python_installation.language_version()
    common_cflags += '-DLIBPYTHON_VERSION=@0@'.format(python_version)
    common_cflags += '-DHAVE_LIBPYTHON' + python_version[0]
endif

##################################
# -Dwith-libunwind build option #
##################################

libunwind_dep = dependency('libunwind', required: get_option('with-libunwind'))
libunwind_is_enabled = get_option('debug') and libunwind_dep.found()
if libunwind_is_enabled
    common_cflags += '-DHAVE_LIBUNWIND'
endif

#################################
# -Dwith-libstdcxx build option #
#################################

cxa_demangle_is_enabled = false
cxa_demangle_dep = []
have_cxa_demangle_code = run_command('cat', files('check-deps/__cxa_demangle.c')).stdout().strip()
have_cxa_demangle_compiles = cc.compiles(have_cxa_demangle_code, name: 'cxa_demangle check', args: ['-lstdc++'])
if get_option('with-libstdcxx').auto()
    if have_cxa_demangle_compiles
        cxa_demangle_dep = cc.find_library('stdc++', required: true)
        cxa_demangle_is_enabled = true
        common_cflags += '-DHAVE_CXA_DEMANGLE'
        message('Enabling libstdc++')
    else
        message('Disabling libstdc++')
    endif
elif get_option('with-libstdcxx').enabled()
    if have_cxa_demangle_compiles
        cxa_demangle_dep = cc.find_library('stdc++', required: true)
        cxa_demangle_is_enabled = true
        common_cflags += '-DHAVE_CXA_DEMANGLE'
        message('Enabling libstdc++ (enabled by: with-libstdcxx)')
    else
        error('Failed to compile and run check-deps/__cxa_demangle.c')
    endif
else
    message('Disabling libstdc++ (disabled by: with-libstdcxx)')
endif

############################
# -Dwith-perf build option #
############################

perf_clockid_is_enabled = false
have_perf_clockid_code = run_command('cat', files('check-deps/__perf_clockid.c')).stdout().strip()
have_perf_clockid_compiles = cc.compiles(have_perf_clockid_code, name: 'perf clockid check')
if get_option('with-perf').auto()
    if have_perf_clockid_compiles
        perf_clockid_is_enabled = true
        common_cflags += '-DHAVE_PERF_CLOCKID'
        message('Enabling perf event support')
    else
        message('Disabling perf event support')
    endif
elif get_option('with-perf').enabled()
    if have_perf_clockid_compiles
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
have_perf_ctxsw_compiles = cc.compiles(have_perf_ctxsw_code, name: 'perf context switch check')
if get_option('with-schedule').auto()
    if have_perf_ctxsw_compiles
        perf_ctxsw_is_enabled = true
        common_cflags += '-DHAVE_PERF_CTXSW'
        message('Enabling scheduler event support')
    else
        message('Disabling scheduler event support')
    endif
elif get_option('with-schedule').enabled()
    if have_perf_ctxsw_compiles
        perf_clockid_is_enabled = true
        common_cflags += '-DHAVE_PERF_CLOCKID'
        message('Enabling scheduler event support (enabled by: with-schedule)')
    else
        error('Failed to compile and run check-deps/__perf_context_switch.c')
    endif
else
    message('Disabling scheduler event support (disabled by: with-schedule)')
endif

#########################
# required dependencies #
#########################

libpthread_dep = dependency('threads')
libdl_dep = cc.find_library('dl', required: false)
librt_dep = cc.find_library('rt', required: false)

###########
# version #
###########

version_sh = find_program('misc/version.sh')
version_sh_cmd = '$(git describe --tags --abbrev=4 --match="v[0-9].[0-9]*" 2> /dev/null || echo v' + meson.project_version() + ')'
version_h = custom_target(
    'gen_version_h',
    output: 'version.h',
    command: [program_shell, '-c', '@0@ @OUTPUT@ @1@ @2@ . > /dev/null'.format(version_sh.path(), version_sh_cmd, arch)],
    env: [
        'UFTRACE_HAVE_LIBCAPSTONE=@0@'        .format(libcapstone_is_enabled  ? 'on' : 'off'),
        'UFTRACE_HAVE_LIBDW=@0@'              .format(libdw_is_enabled        ? 'on' : 'off'),
        'UFTRACE_HAVE_LIBLUAJIT=@0@'          .format(libluajit_is_enabled    ? 'on' : 'off'),
        'UFTRACE_HAVE_LIBPYTHON=@0@'          .format(libpython_is_enabled    ? 'on' : 'off'),
        'UFTRACE_HAVE_LIBNCURSES=@0@'         .format(libncursesw_is_enabled  ? 'on' : 'off'),
        'UFTRACE_HAVE_PERF_CLOCKID=@0@'       .format(perf_clockid_is_enabled ? 'on' : 'off'),
        'UFTRACE_HAVE_PERF_CONTEXT_SWITCH=@0@'.format(perf_ctxsw_is_enabled   ? 'on' : 'off'),
    ],
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
    libncursesw_dep,
    libpthread_dep,
    libpython_dep,
    librt_dep,
    libunwind_dep,
]

libmcount = shared_library(
    'mcount', [libmcount_arch_sources, libmcount_arch_asm_sources, libmcount_sources, version_h],
    include_directories: [libmcount_arch_include],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags],
    link_args: [common_ldflags],
    install: true,
    gnu_symbol_visibility: 'hidden',
)

libmcount_fast = shared_library(
    'mcount-fast', [libmcount_arch_sources, libmcount_arch_asm_sources, libmcount_sources, version_h],
    include_directories: [libmcount_arch_include],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags, '-DDISABLE_MCOUNT_FILTER'],
    link_args: [common_ldflags],
    install: true,
    gnu_symbol_visibility: 'hidden',
)

libmcount_single = shared_library(
    'mcount-single', [libmcount_arch_sources, libmcount_arch_asm_sources, libmcount_sources, version_h],
    include_directories: [libmcount_arch_include],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags, '-DSINGLE_THREAD'],
    link_args: [common_ldflags],
    install: true,
    gnu_symbol_visibility: 'hidden',
)

libmcount_fast_single = shared_library(
    'mcount-fast-single', [libmcount_arch_sources, libmcount_arch_asm_sources, libmcount_sources, version_h],
    include_directories: [libmcount_arch_include],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags, '-DDISABLE_MCOUNT_FILTER', '-DSINGLE_THREAD'],
    link_args: [common_ldflags],
    install: true,
    gnu_symbol_visibility: 'hidden',
)

libmcount_fast_nop = shared_library(
    'mcount-nop', [libmcount_nop_sources, version_h],
    include_directories: [],
    dependencies: [libmcount_base_deps],
    c_args: [common_cflags, libmcount_cflags, '-DDISABLE_MCOUNT_FILTER', '-DSINGLE_THREAD'],
    link_args: [common_ldflags],
    install: true,
    gnu_symbol_visibility: 'hidden',
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
    gnu_symbol_visibility: 'hidden',
)

libtraceevent_dep = declare_dependency(
    include_directories: [libtraceevent_include],
    link_with: [libtraceevent],
)

###########
# uftrace #
###########

uftrace_include = [
    include_directories('.'),
    include_directories('cmds'),
]

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
    libncursesw_dep,
    libpthread_dep,
    libpython_dep,
    librt_dep,
    libtraceevent_dep,
    libunwind_dep,
]

uftrace = executable(
    'uftrace', [uftrace_sources, version_h],
    include_directories: [uftrace_include],
    dependencies: [uftrace_deps],
    c_args: [common_cflags, uftrace_cflags],
    link_args: [common_ldflags],
    install: true,
    gnu_symbol_visibility: 'hidden',
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
    libunwind_dep,
]

dbginfo = executable(
    'dbginfo', [dbginfo_sources],
    dependencies: [dbginfo_deps],
    c_args: [common_cflags, dbginfo_cflags],
    link_args: [common_ldflags],
    build_by_default: true,
    gnu_symbol_visibility: 'hidden',
)

#############
# demangler #
#############

demangler_sources = [
    'misc/demangler.c',
    'utils/demangle.c',
    'utils/debug.c',
    'utils/utils.c',
    version_h,
]

demangler_deps = [
    cxa_demangle_dep,
    libunwind_dep,
]

demangler = executable(
    'demangler', [demangler_sources],
    dependencies: [demangler_deps],
    c_args: [common_cflags, demangler_cflags],
    link_args: [common_ldflags],
    build_by_default: true,
    gnu_symbol_visibility: 'hidden',
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
    libunwind_dep,
]

symbols = executable(
    'symbols', [symbols_sources],
    dependencies: [symbols_deps],
    c_args: [common_cflags, symbols_cflags],
    link_args: [common_ldflags],
    build_by_default: true,
    gnu_symbol_visibility: 'hidden',
)

#########
# tests #
#########

unittests_includes = [
    include_directories('.'),
    include_directories('tests', 'arch/' + arch),
]

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
    version_h,
]

unittests_deps = [
    cxa_demangle_dep,
    libcapstone_dep,
    libdl_dep,
    libdw_dep,
    libelf_dep,
    libluajit_dep,
    libncursesw_dep,
    libpthread_dep,
    libpython_dep,
    librt_dep,
    libtraceevent_dep,
    libunwind_dep,
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
    gnu_symbol_visibility: 'hidden',
)

if not cross_compiling
    run_target('unittest', command: [unittests])

    run_target('runtest',
        command: [program_shell, '-c', 'cd @0@ && ./runtest.py'.format(tests_dir)],
        env: ['objdir=@0@'.format(meson.current_build_dir())],
        depends: [
            libmcount,
            libmcount_fast,
            libmcount_single,
            libmcount_fast_single,
            libmcount_fast_nop,
            uftrace,
        ],
    )

    run_target('tests', command: ['ninja', 'unittest', 'runtest'])
endif

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
        man_page_target = man_page.replace('-', '_')

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

run_target('ctags',
    command: [
        'find', meson.source_root(), '-name', '*.[chS]',
        '-o', '-path', '.*/tests', '-prune',
        '-o', '-path', '*/check-deps', '-prune',
        '-type', 'f',
        '-exec', 'ctags', '--regex-asm=\'/^(GLOBAL|ENTRY|END)\(([^)]*)\).*/\2/\'', '{}', '+',
    ]
)

#############
# summaries #
#############

summary({
    'prefix': get_option('prefix'),
    'bindir': get_option('bindir'),
    'libdir': get_option('libdir'),
    'mandir': get_option('mandir'),
}, section: 'Directories')

summary({
    'libcapstone'  : libcapstone_is_enabled,
    'libdw'        : libdw_is_enabled,
    'libelf'       : libelf_is_enabled,
    'libluajit'    : libluajit_is_enabled,
    'libpython'    : libpython_is_enabled,
    'libncursesw'  : libncursesw_is_enabled,
    'cxa_demangle' : cxa_demangle_is_enabled,
    'perf event'   : perf_clockid_is_enabled,
    'perf schedule': perf_ctxsw_is_enabled,
    'libunwind'    : libunwind_is_enabled,
}, section: 'Configuration', bool_yn: true)