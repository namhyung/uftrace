QUICK GUIDE
===========

리눅스 배포판에서는 다음의 명령어들을 사용하여 uftrace를 빌드하고 설치할 수 있습니다.

    $ sudo misc/install-deps.sh    # optional for advanced features
    $ ./configure                  # --prefix can be used to change install dir
    $ make
    $ sudo make install

더 자세한 사항은 아래의 내용을 참고하십시오.


GETTING THE SOURCE
==================
최신 버전의 uftrace는 Github에서 사용할 수 있습니다.

  https://github.com/namhyung/uftrace


DEPENDENCY
==========

uftrace는 C언어로 작성되었고, 외부 의존성을 최소화하였습니다.
현재, utrace는 외부 라이브러리 없이 빌드 가능합니다. 하지만 더 많은 고급 기능들을 사용하기 위해서는 아래의 라이브러리들을 설치하는 것이 좋습니다.

먼저, uftrace의 종속성을 제대로 감지할 수 있도록 하는 `pkg-config`가 시스템에 설치되어 있는지 확인해야 합니다.
만약, 그렇지 않다면 이미 설치되어 있어도 일부 패키지가 감지되지 않아 uftrace의 일부 기능이 비활성화될 수 있습니다.

과거에는 uftrace가 ELF 파일 조작을 위해 elfutils 프로젝트의 `libelf`에 의존했습니다.
더 이상 `libelf`가 필수는 아니지만 ELF 실행파일을 더 잘 처리하기 위해서는 설치하는 것을 권장합니다.
또한, DWARF 디버그 정보를 처리하기 위해서는 `libdw` 라이브러리를 설치하는 것이 좋습니다.
libdw 자체는 `libelf`에 의존하므로 `libdw`만 설치하면 됩니다.

debian기반의 시스템에서는(예: Ubuntu) `libdw-dev` 패키지가 필요한 라이브러리 및 파일들을 제공해 줍니다.

    $ sudo apt-get install libdw-dev

redhat기반의 시스템에서는(예: Fedora, RHEL) `elfutils-devel`이 필요합니다.

    $ sudo dnf install elfutils-devel

또한, uftrace에서는 libstdc++ 라이브러리를 사용하여 C++ symbol들을 완전하게 demangling합니다.
하지만 uftrace는 더 짧은 symbol name을 위한 자체 demangler를 가지고 있으므로 libstdc++ 라이브러리가 필수는 아닙니다.
(uftrace의 자체 demanlger는 인수와 템플릿 등을 생략합니다.)

ncursesw 라이브러리는 콘솔에서 테스트 사용자 인터페이스(TUI)를 구현하는데 사용됩니다.
ncurses(w) 라이브러리는 터미널 처리 루틴 위에서 빌드된 `uftrace tui` 명령어를 제공합니다.
이는 트레이스 데이터 분석의 사용자 경험을 향상해 주므로 만약, `uftrace graph`나 `uftrace report`와 같은 작업을 자주 수행하는 경우 설치하는 것이 좋습니다.

또한, 마크다운 문서에서 man 페이지를 빌드하려면 `pandoc`이 필요합니다.


BUILD
=====

uftrace를 빌드하려면 먼저, gcc 및 make와 같은 기본 소프트웨어 개발 도구들을 설치해야 합니다. 그리고 종속성있는 패키지들도 함께 설치해야 합니다.
자세한 내용은 DEPENDENCY 부분을 참조하십시오.

필요한 소프트웨어들을 설치한 후에는 `configure`를 실행하여 설치 경로 및 기타 기능들을 설정해야 합니다. `configure`실행 시 디폴트도 /usr/local 경로에 uftrace를 설치합니다.
만약, uftrace를 다른 위치에 설치하려면 `prefix`변수를 설정해주면 됩니다. (아래를 참조)

    $ ./configure --prefix=/usr

prefix 경로와 감지된 기능들이 다음과 같이 표시됩니다:

    uftrace detected system features:
    ...         prefix: /usr
    ...         libelf: [ on  ] - more flexible ELF data handling
    ...          libdw: [ on  ] - DWARF debug info support
    ...      libpython: [ on  ] - python scripting support
    ...      libluajit: [ OFF ] - luajit scripting support
    ...    libncursesw: [ on  ] - TUI support
    ...   cxa_demangle: [ on  ] - full demangler support with libstdc++
    ...     perf_event: [ on  ] - perf (PMU) event support
    ...       schedule: [ on  ] - scheduler event support
    ...       capstone: [ on  ] - full dynamic tracing support
    ...      libunwind: [ OFF ] - stacktrace support (optional for debugging)

그런 다음 `make`를 실행하여 소스 파일을 빌드할 수 있습니다.

    $ make

위 명령어는 uftrace를 빌드하며, 명령어의 실행 결과로 uftrace 실행파일을 현재 경로에 생성합니다.
이 단계까지는 테스트 목적으로 나쁘지 않지만, 일반적인 사용을 위해서는
아래 명령어로 설치하는 것이 좋습니다.

    $ sudo make install

다음은 빌드의 출력은 리눅스 커널 스타일과 유사하게 보여주며, 사용자는 V=1을 사용하여 원래의 빌드 명령어 라인들을 볼 수 있습니다. (커널과 유사)

    $ make V=1


CONFIGURATION
=============

uftrace는 사용자의 환경 설정을 저장하기 위해 자체 버전의 스크립트 설정을 실행합니다.
config 파일(`.config`)이 없는 경우, 빌드 시 기본 옵션으로 config 파일이 생성됩니다.
사용자는 이 스크립트 파일을 사용하여 사용자 지정 설치 경로 및 빌드 경로를 설정할 수 있습니다.

    $ ./configure --help
    Usage: ./configure [<options>]

      --help                print this message
      --prefix=<DIR>        set install root dir as <DIR>        (default: /usr/local)
      --bindir=<DIR>        set executable install dir as <DIR>  (default: ${prefix}/bin)
      --libdir=<DIR>        set library install dir as <DIR>     (default: ${prefix}/lib/uftrace)
      --mandir=<DIR>        set manual doc install dir as <DIR>  (default: ${prefix}/share/man)
      --objdir=<DIR>        set build dir as <DIR>               (default: ${PWD})
      --sysconfdir=<DIR>    override the etc dir as <DIR>

      --with-elfutils=<DIR> search for elfutils in <DIR>/include and <DIR>/lib

      --without-libelf      build without libelf (and libdw)     (even if found on the system)
      --without-libdw       build without libdw                  (even if found on the system)
      --without-libstdc++   build without libstdc++              (even if found on the system)
      --without-libpython   build without libpython              (even if found on the system)
      --without-libluajit   build without libluajit              (even if found on the system)
      --without-libncurses  build without libncursesw            (even if found on the system)
      --without-capstone    build without libcapstone            (even if found on the system)
      --without-perf        build without perf event             (even if available)
      --without-schedule    build without scheduler event        (even if available)

      --arch=<ARCH>         set target architecture              (default: system default arch)
                            e.g. x86_64, aarch64, i386, or arm
      --cross-compile=<CROSS_COMPILE>
                            Specify the compiler prefix during compilation
                            e.g. CC is overridden by $(CROSS_COMPILE)gcc
      --cflags=<CFLAGS>     pass extra C compiler flags
      --ldflags=<LDFLAGS>   pass extra linker flags

      -p                    preserve old setting

      Some influential environment variables:
        ARCH                Target architecture    e.g. x86_64, aarch64, i386, or arm
        CROSS_COMPILE       Specify the compiler prefix during compilation
                            e.g. CC is overridden by $(CROSS_COMPILE)gcc
        CFLAGS              C compiler flags
        LDFLAGS             linker flags

또한, 목표 아키텍처 및 컴파일러 옵션들(예: CC, CFLAGS)도 설정할 수 있습니다.

외부 라이브러리나 시스템 동작에 의존하는 일부 기능들도 비활성화할 수 있습니다.
예를 들어, --without-libpython 옵션은 스크립팅 기능을 비활성화합니다. - `uftrace script` 명령어는 여전히 존재하지만 작동하지는 않을 것입니다.

크로스 컴파일을 위해서는 아래와 같이 toolchain을 설정할 수 있습니다:

    $ export CROSS_COMPILE=/path/to/cross/toolchain/arm-unknown-linux-gnueabihf-
    $ ARCH=arm CFLAGS='--sysroot /path/to/sysroot' ./configure
        or
    $ ./configure --arch=arm --cflags='--sysroot /path/to/sysroot' \
          --cross-compile=/path/to/cross/toolchain/arm-unknown-linux-gnueabihf-

이는 이미 sysroot 경로에 크로스 컴파일된 `libelf`가 설치되어 있다고 가정합니다.
만약, 설치되지 않았다면 소스로부터 빌드하거나(아래를 참조) `--with-elfutils=<PATH>`를 이용하여 다른 경로에서도 사용할 수 있습니다.

Android 9+용으로 컴파일하려면, CC 환경 변수를 내보내고 아직 구현되지 않은 파이썬 및 libstdc++ 지원을 비활성화하십시오.
예를 들어, Android AArch64를 위해 설정하려면 다음과 같이 하십시오:

    $ export CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang
    $ export LD=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld
    $ ./configure --arch=aarch64 --cross-compile=aarch64-linux-gnu- --without-libpython --without-libstdc++

안드로이드에서는 `-fpatchable-function-entry`로 계측화된 프로그램을 컴파일하는 것이 권장됩니다.
`-finstrument-functions`나 `-pg`도 사용할 수 있지만,
그 경우에는 안드로이드 런타임이 `__cyg_profile_func_enter` 또는 `mcount`를 포함하지 않기 때문에 프로그램을 `-Wl,-z,undefs`와 함께 링크해야 합니다.

지금까지 안드로이드는 AArch64와 x86_64에서 테스트되었습니다.

BUILD WITH ELFUTILS (libelf)
============================

대상 시스템에 libelf/libdw가 설치되어 있지 않은 경우 uftrace 빌드를 위해 libelf/libdw를 수동으로 컴파일하는 것이 유용할 수 있습니다.
`misc/install-elfutils.sh`는 elfutils에 있는 라이브러리인 libelf와 libdw를 다운로드하고 빌드하는 방법을 제공합니다.

아래는 libelf/libdw와 함께 uftrace를 컴파일하는 방법입니다.

    $ export CROSS_COMPILE=arm-linux-gnueabi-
    $ export ARCH=arm
    $ export CFLAGS="-march=armv7-a"
    $ ./misc/install-elfutils.sh --prefix=/path/to/install
    $ ./configure --prefix=/path/to/install --with-elfutils=/path/to/install

    $ make
    $ make install

`misc/install-elfutils.sh`는 elfutils를 다운로드하고 빌드하며 libelf와 libdw 두 라이브러리를 prefix 경로에 설치합니다.
설치된 libelf와 libdw는 `configure` 스크립트의 `--with-elfutils` 옵션을 사용하여 찾을 수 있습니다.


번역자
=====
권석민 <ksm012015@gmail.com>
