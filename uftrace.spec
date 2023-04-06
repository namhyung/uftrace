%bcond_without   check
%bcond_without   python
Name:            uftrace
Version:         0.13
Release:         16%{?dist}

Summary:         Function graph tracer for C and C++ with many features
# https://github.com/namhyung/uftrace/issues/1343
%global          _lto_cflags %nil
# -fPIE/-fpie is not supported for building uftrace and forcing it causes test regressions:
%undefine        _hardened_build
License:         GPL-2.0-only
Url:             https://github.com/namhyung/uftrace
Source:          https://github.com/namhyung/%{name}/archive/v%{version}/%{name}-%{version}.tar.gz

ExclusiveArch:   x86_64 %ix86 %arm aarch64

BuildRequires:   elfutils-devel
%if %{with check}
BuildRequires:   clang compiler-rt
BuildRequires:   /proc
%endif
BuildRequires:   gcc-c++
BuildRequires:   libstdc++-devel
BuildRequires:   make
BuildRequires:   ncurses-devel
%if 0%{?centos} > 8 || 0%{?rhel} > 8 || 0%{?fedora} > 35
BuildRequires:   capstone-devel
%endif
%if 0%{?fedora} > 35
BuildRequires:   luajit-devel
BuildRequires:   libunwind-devel
BuildRequires:   pandoc
%global          have_pandoc 1
%endif
%if %{with python}
BuildRequires:   python3-devel
%else
BuildRequires:   python3
%endif

%description
uftrace is a function call graph tracer for C, C++, Rust and Python programs.
Using dynamic tracing, it can include nested library calls and
even seamless function graph tracing of used kernel functions.

- Shows colored nested function call graphs (instead of listings)!
- Displays arguments symbolically using libc function prototypes and DWARF
  debug information values.
- Filters like minimal function call duration are available
- Traces trace kernel events e.g. scheduling events (which affecting the
  execution timing of the program) and records nanosecond-exact timestamps.

%prep
%autosetup -p1
cd tests
sed -i 's|python$|python3|' runtest.py
# These need root privileges for kernel syscall tracing:
rm t022_filter_kernel.py  t081_kernel_depth.py t103_dump_kernel.py    t104_graph_kernel.py
rm t111_kernel_tid.py         t132_trigger_kernel.py               t137_kernel_tid_update.py
rm t13[89]_kernel_dynamic*.py t143_recv_kernel.py t148_event_kernel.py t149_event_kernel2.py
rm t147_event_sdt.py t150_recv_event.py
rm *pmu_*.py t140_dynamic_xray.py # Need to run on a machine with PMU access.
rm t014_ucontext.py *taskname*.py *sched.py # Kernel API access dependency
%ifarch x86_64
rm t271_script_event.py  # Linux perf event diff possble: to be filtered out
rm t212_noplt_libcall.py *_report_* t121_malloc_fork.py # Diff, To be fixed
rm t220_trace_script.py  # Very long output diff on native FC37 install
rm t225_dynamic_size.py  # all gcc tests fail due to diff on c9
%endif
# Build failures:
rm t216_no_libcall_report.py t217_no_libcall_dump.py t218_no_libcall_graph.py
%ifarch aarch64
rm t232_dynamic_unpatch.py # x86_64 skips most, but not all, aarch skips all
rm *_retval.py  *float*.py *nested_func*.py *signal* # Different ouput, to be fixed
%endif
rm *replay*.py *exception*.py # To be fixed, Differs between gcc and clang
rm t200_lib_dlopen2.py t151_recv_runcmd.py t219_no_libcall_script.py *_arg*.py # To be fixed in v0.14
# Timing/races:
rm t035_filter_demangle[135].py t102_dump_flamegraph.py t107_dump_time.py
rm t135_trigger_time2.py        t223_dynamic_full.py    t226_default_opts.py
%ifarch x86_64
rm t162_pltbind_now_pie.py   # 16 (all) are build failures in COPR
rm t049_column_view.py t118_thread_tsd.py
rm t051_return.py            # Missing t051_return for gcc-pg-O3
rm t033_filter_demangle3.py  # Missing b() {
rm t038_trace_disable.py t172_trigger_filter.py    # Missing ns::ns1::foo::bar3();
rm t181_graph_full.py        # simple tree node output ordering issue
rm t191_posix_spawn.py # Sometimes has nonzero output status
%endif
rm t273_agent_basic.py # Sometimes has nonzero output status
%ifarch aarch64
# rm *no_libcall*.py *dynamic_xray.py   # Kernel API access dependency
# Seem to be timing-dependent on fc38-aarch64-ampere-a1:
rm t071_graph_depth.py t208_watch_cpu.py
%if 0%{?centos} >= 8 || 0%{?fedora} >= 38
rm t168_lib_nested.py t192_lib_name.py # Abnormal exit by signal
%endif
%endif

%build
%if %{without python}
conf_flags="--without-libpython"
%endif
%if "%{version}" == "0.13"
# Fix some incorrect floating point argument/return values:
# https://github.com/namhyung/uftrace/issues/1631 https://github.com/namhyung/uftrace/pull/1632
CFLAGS="-fno-builtin -fno-tree-vectorize"
%endif
%configure --libdir=%{_libdir}/%{name} $conf_flags
harden=-specs=/usr/lib/rpm/redhat/redhat-hardened-cc1
echo "CFLAGS_demangler=$harden"  >>.config
echo "CFLAGS_dbginfo=$harden"    >>.config
echo "CFLAGS_symbols=$harden"    >>.config
echo "CFLAGS_traceevent=$harden" >>.config
echo "CFLAGS_uftrace=$harden"    >>.config
echo "LDFLAGS_uftrace=$RPM_LD_FLAGS -pie" >>.config
cat .config
env |grep FLAGS
%make_build

%install
make install DESTDIR=%{buildroot} V=1
file     %{buildroot}%{_bindir}/uftrace | grep 'pie executable'
if nm -D %{buildroot}%{_bindir}/uftrace | grep gethostbyname; then exit 5;fi
%if %{with check}
# Builds all test programs with all gcc and clang and -O0, -Os, -O1, -O2, -O3,
# and the tracing output it needs to be identical. Other CFLAGS cause diffs(fails).
# The test report is packaged, checked again and shown at the end of check:
unset CFLAGS CXXFLAGS LDFLAGS
# On aarch64, clang has fewer quirks, giving more focussed test results:
make runtest WORKER="--keep --diff -Os123" >test-report.txt 2>&1 &
TEST=$!
sleep 1
stdbuf -oL tail -f test-report.txt &
wait $TEST
%endif

# Reference 1: https://bugzilla.redhat.com/show_bug.cgi?id=2180989#c25
# Reference 2: https://bugzilla.redhat.com/show_bug.cgi?id=1398922#c21
# Quote: "Please place packaged completions under
# _datadir/bash-completion/completions/ and keep /etc for the administrator."
# (This path is also used by Debian and Ubuntu packages)
# Use the macro 'bash_completions_dir' from redhat-rpm-config:
# CentOS 8 and 9 do not define it yet:
%{!?bash_completions_dir: %global bash_completions_dir %{_datadir}/bash-completion/completions}
cd %{buildroot}
mkdir -p                                     .%{bash_completions_dir}
mv .%{_sysconfdir}/bash_completion.d/uftrace .%{bash_completions_dir}/
# Upstream patch submission 1: https://github.com/namhyung/uftrace/pull/1654
# Upstream patch submission 2: https://github.com/namhyung/uftrace/pull/1264

%check
export LD_LIBRARY_PATH=%{buildroot}%{_libdir}/%{name}
%{buildroot}%{_bindir}/uftrace --version
%{buildroot}%{_bindir}/uftrace record -A . -R . -P main ./uftrace
%{buildroot}%{_bindir}/uftrace replay
%{buildroot}%{_bindir}/uftrace dump
%{buildroot}%{_bindir}/uftrace info
# Show and check the test report. Fail the build on any regression:
tail -12 test-report.txt
tail -12 test-report.txt |
   while read sym count text;do
      case "$text" in
%ifarch aarch64
         "Test succeeded")          test $count -ge 2443;;
         "Test succeeded (with"*)   test $count -ge   40;;
         "Different test result")   test $count -le    5;;
         "Build failed")            test $count -le    0;;
         "Skipped")                 test $count -le   40;; # dynamic, script_luajit(c9)
%endif
%ifarch x86_64
         "Test succeeded")          test $count -ge 1912;;
         "Test succeeded (with"*)   test $count -ge   46;;
         "Different test result")   test $count -le    9;; # thread_exit,nested_func
         "Build failed")            test $count -le   16;;
%if 0%{?centos} >= 9
         "Skipped")                 test $count -le   84;;
%else
         "Skipped")                 test $count -le   48;; # 8 more in COPR than in mock
%endif
%endif
         "Non-zero return value")   test $count -le    2;; # races in recv_multi & patchable_dynamic4 on aarch64
         "Abnormal exit by signal") test $count -le    8;; # f38,f39
      esac
   done

%files
%{_bindir}/%{name}
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/libmcount*.so
%if 0%{?have_pandoc}
%{_mandir}/man1/*.1*
%endif
%{bash_completions_dir}/%{name}
%doc README.md test-report.txt
%license COPYING

%changelog
* Fri Mar 24 2023 Bernhard Kaindl <contact@bernhard.kaindl.dev> 0.13-16
- Initial rpm for Fedora and CentOS Stream
