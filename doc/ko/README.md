[![Build Status](https://app.travis-ci.com/namhyung/uftrace.svg?branch=master)](https://app.travis-ci.com/namhyung/uftrace)
[![Coverity scan](https://scan.coverity.com/projects/12421/badge.svg)](https://scan.coverity.com/projects/namhyung-uftrace)

uftrace
=======

uftrace 는 C, C++, Rust, Python 으로 작성된 프로그램의 실행 흐름을
추적(trace)하며 기록하고 분석하는 도구이다.

uftrace는 각 함수의 시작과 끝을 후킹하여 타임스탬프 및 함수 인자, 반환값 등을 기록한다.
uftrace는 유저와 커널 함수 뿐 아니라 라이브러리 함수 및 시스템 이벤트를 추적하여
단일한 시간 흐름 상에서 통합된 실행 과정으로 보여줄 수 있다.

초기에, uftrace는 컴파일러 지원을 이용한 함수 추적만을 제공해 주었다.
그러나, 현재는 각 함수 프롤로그의 명령어를 분석하고 동적이고 선택적으로
명령어들을 패치함으로써, 재컴파일 없이 함수 호출을 추적할 수 있다.

사용자는 Python/Juajit API를 이용해 함수의 시작과 종료에 대한 스크립트를
작성하고, 실행해 특정 용도에 맞는 커스텀 도구를 만들 수 있다.

uftrace는 추적 데이터의 양을 줄이기 위해 다양한 필터 기능을 제공하며,
Chrome trace viewer와 Flame graph, 혹은 graphviz와 mermaid와 호환되는
호출 그래프 다이어그램을 통한 시각화를 제공해 실행 흐름을 한 눈으로
볼 수 있다.

이 도구는 Linux 커널의 ftrace 프레임워크에 크게 영감을 받았고, uftrace 이름의
뜻은 user와 ftrace 단어를 합쳐 만들었다.

이러한 프로그램들을 기록할 수 있다:
- 유저 스페이스 C/C++/Rust 함수들 (런타임에서 동적으로 패치가 가능하거나,
  코드가 `-pg`, `-finstrument-functions`로 컴파일되었거나, 선택적
  NOP 패치를 위해 `-fpatchable-function-entry=N`로 컴파일된 경우)
- C/C++/Rust 라이브러리 함수 (PLT hooking 이용)
- Python 함수 (Python의 추적/프로필 기반 이용)
- 커널 함수 (리눅스 커널의 ftrace 프레임워크 이용)
- 커널 추적 이벤트 (리눅스 커널의 이벤트 트레이싱 프레임워크 이용)
- 작업 생성, 종료, 스케줄링 이벤트 (리눅스의 perf_event 이용)
- 목표 바이너리 혹은 라이브러리의 유저 스페이스 이벤트 (SystemTap SDI ABI 이용)
- 주어진 함수의 PMU 카운터 값 (리눅스의 perf_event 이용)

기록된 데이터를 이용해, uftrace는 다음과 같은 기능을 제공한다:
- 중첩 함수 호출 그래프를 시각화해 준다.
- libc 함수 프로토타입과 DWARF 디버그 정보를 이용해 함수 인자와
  반환 값을 심볼로 표시해 준다.
- 추적 데이터 양을 줄이기 위해 필터 기능을 적용한다 (record 및 replay 시 모두 가능)
- 추적 데이터에서 메타데이터를 추출한다. (e.g. 추적이 수행된 시스템의 정보)
- 추적된 프로그램 및 라이브러리 함수의 심볼 테이블 및 메모리 맵을 생성한다.
- 추적 데이터로부터 프로그램의 작업 관계 트리(부모/자식 관계)를 생성한다.

uftrace는 프로그램 실행 및 성능 분석을 위해 함수 호출 기간별 필터링과 같은
많은 명령 및 필터를 지원한다.

![uftrace-live-demo](../uftrace-live-demo.gif)

 * 홈페이지: https://github.com/namhyung/uftrace
 * 튜토리얼: https://github.com/namhyung/uftrace/wiki/Tutorial
 * 채팅방: https://gitter.im/uftrace/ko
 * 메일링 리스트: [uftrace@googlegroups.com](https://groups.google.com/forum/#!forum/uftrace)
 * 발표 영상: https://youtu.be/LNav5qvyK7I


기능
========

uftrace는 각 실행되는 함수들을 추적하고 소요된 시간을 보여준다.

일반적으로, 이런 과정이 가능하기 위해선, 프로그램이 `-pg` 혹은
`-fpatchable-function-entry=5` (aarch64 환경에선 `=2` 도 충분함)로
컴파일되어야 한다. 전체 동적 추적 기능 (`-P.`|`--patch=.`)을
이용한다면 (디버깅 정보가 있거나 심볼 정보가 별도 파일에 존재하는 경우)
uftrace는 모든 실행 파일을 추적 가능하다.

uftrace는 라이브러리 콜을 추적하기 위해 주어진 실행 파일의 PLT에 훅을 걸고,
(`-l`|`--nest-libcall`)옵션을 이용하면 공유 라이브러리의 프로시저
연결 테이블(PLT)에도 훅을 걸게 된다. 깊이는 `-D<num>`을 이용해 제한할
수 있다. 1일 경우 첫 단계만 추적한다.

(`-a`|`--auto-args`) 옵션을 이용하면, uftrace는 자동으로 알려진 함수에 대해
인자와 반환 값을 기록한다. 추가적인 디버그 정보가 없다면, 이것은 표준
(C 언어 혹은 시스템) 라이브러리의 API 함수를 포함한다. 이는 `-P.` 혹은
`-l` 옵션과 함께 사용할 수 있다. 예를 들어, `-la` 옵션은 디버깅
정보가 없는 파일도 추적이 가능하며, 중첩된 함수 호출 추적을 지원한다.

추가로, `-a` 옵션은 `--srcline`과 동일하며 소스의 라인 위치 정보를 기록한다.
그리고 이는 `uftrace replay --srcline` 혹은 `uftrace tui`를 통해
볼 수 있다. 사용자는 바로 해당 소스 코드를 에디터로 열어볼 수 있다.
참고 : https://uftrace.github.io/slide/#120

프로그램의 디버그 정보 (`gcc -g`)가 존재한다면, `--auto-args`는 컴파일된
사용자 프로그램 내부의 함수에서도 작동한다.

인자 정보가 존재하지 않는 경우, (`-A udev_new@arg1/s`)와 같이 인자 정보를
명령줄이나 옵션 파일에 전달할 수 있다.

예:
```py
$ uftrace record -la -A udev_new@arg1/s lsusb >/dev/null
$ uftrace replay -f+module
혹은 간단히:
$ uftrace -la -A udev_new@arg1/s -f+module lsusb  # -f+module adds the module name
# DURATION     TID        MODULE NAME   FUNCTION
 306.339 us [ 23561]            lsusb | setlocale(LC_TYPE, "") = "en_US.UTF-8";
   1.163 us [ 23561]            lsusb | getopt_long(1, 0x7fff7175f6a8, "D:vtP:p:s:d:Vh") = -1;
            [ 23561]            lsusb | udev_new("POSIXLY_CORRECT") {
   0.406 us [ 23561] libudev.so.1.7.2 |   malloc(16) = 0x55e07277a7b0;
   2.620 us [ 23561]            lsusb | } /* udev_new */
            [ 23561]            lsusb | udev_hwdb_new() {
   0.427 us [ 23561] libudev.so.1.7.2 |   calloc(1, 200) = 0x55e07277a7d0;
   5.829 us [ 23561] libudev.so.1.7.2 |   fopen64("/etc/systemd/hwdb/hwdb.bin", "re") = 0;
```

추가적으로, uftrace는 함수 단계에서 구체적인 실행 흐름을 표현할 수 있으며,
어떤 함수가 가장 긴 수행 시간을 가지는지 표현할 수 있다.
그리고 실행 환경의 정보를 보여줄 수도 있다.

당신은 필터를 이용해 특정 함수를 포함하거나 제외할 수 있다.
추가로, 함수 인자나 반환 값은 저장한 후 다음에 출력할 수 있다.

uftrace는 멀티프로세스와 멀티스레드 애플리케이션을 지원한다.
root 권한이 있고 `CONFIG_FUNCTION_GRAPH_TRACER=y` 설정이 켜진
상태로 커널이 빌드되어 있다면, 커널 함수 또한 추적이 가능하다.

uftrace 빌드 및 설치 방법
================================

리눅스 배포판에서, [misc/install-deps.sh](../../misc/install-deps.sh) 스크립트는
uftrace를 빌드하는 데 필요한 소프트웨어를 설치해 준다. 이는 고급
기능들을 위한 것이며 반드시 설치할 필요는 없지만, 함께 설치하기를
적극 권장한다.

    $ sudo misc/install-deps.sh

요구되는 소프트웨어를 설치한 뒤, 다음과 같이 빌드 및 설치가 가능하다:

    $ ./configure
    $ make
    $ sudo make install

더 자세한 설치방법은, [INSTALL.md](../../INSTALL.md) 파일을 확인하면 된다.


uftrace 사용 방법
==================
uftrace 명령어는 다음과 같은 명령어를 제공한다.

 * [`record`](./uftrace-record.md) : 프로그램을 실행하며 추적 데이터를 저장한다.
 * [`replay`](./uftrace-replay.md) : 추적 데이터 내의 프로그램 실행을 보여준다.
 * [`report`](./uftrace-report.md) : 추적 데이터 내의 수행 통계를 보여준다.
 * [`live`  ](./uftrace-live.md)   : record 와 replay 를 차례로 수행한다. (기본값)
 * [`info`  ](./uftrace-info.md)   : 추적 데이터 내의 시스템 및 프로그램 정보를 보여준다.
 * [`dump`  ](./uftrace-dump.md)   : low-level의 추적 데이터를 보여준다.
 * [`recv`  ](./uftrace-recv.md)   : 네트워크로부터 추적한 데이터를 저장한다.
 * [`graph` ](./uftrace-graph.md)  : 추적 데이터 내의 함수 호출 그래프를 보여준다.
 * [`script`](./uftrace-script.md) : 저장된 추적 데이터의 스크립트를 실행한다.
 * [`tui`   ](./uftrace-tui.md)    : graph와 report를 위한 텍스트 기반 인터페이스를 보여준다.

[사용 가능한 명령어와 옵션](./uftrace.md)을 보기 위해 `-h` 혹은 `--help`
옵션을 사용할 수 있다.

    $ uftrace
    uftrace -- function (graph) tracer for userspace

     usage: uftrace [COMMAND] [OPTION...] [<program>]

     COMMAND:
       record          Run a program and saves the trace data
       replay          Show program execution in the trace data
       report          Show performance statistics in the trace data
       live            Do record and replay in a row (default)
       info            Show system and program info in the trace data
       dump            Show low-level trace data
       recv            Save the trace data from network
       graph           Show function call graph in the trace data
       script          Run a script for recorded trace data
       tui             Show text user interface for graph and report

    Try `uftrace --help' or `man uftrace [COMMAND]' for more information.

만일 하위 명령어를 생략한다면, 기본적으로 record 와 replay 를 차례로
적용한 것과 동일한 `live` 명령어를 수행한다. (하지만 추적 정보를
파일로 저장하진 않는다)

record 명령어로 기록하기 위해선, 실행 파일이 `-pg` (혹은 `-finstrument-functions`)
옵션을 이용해 컴파일되어 프로파일링 코드 (mcount 혹은
__cyg_profile_func_enter/exit로 불리는)가 생성되어야 한다.

x86_64 와 AArch64(ARM64) 아키텍처에서 (재)컴파일 과정이 필요하지 않은 동적 추적 기능이
실험적으로 지원되고 있다. 또한 최근 컴파일러들 중 (여전히 프로그램을
재컴파일해야 하긴 하지만) 비슷한 방식으로 uftrace의 추적 과정에서 생기는
오버헤드를 줄이기 위한 옵션들을 제공하고 있다.
더 자세한 내용은 [dynamic tracing](./uftrace-record.md#dynamic-tracing) 에서 확인해
볼 수 있다.

    $ uftrace tests/t-abc
    # DURATION    TID     FUNCTION
      16.134 us [ 1892] | __monstartup();
     223.736 us [ 1892] | __cxa_atexit();
                [ 1892] | main() {
                [ 1892] |   a() {
                [ 1892] |     b() {
                [ 1892] |       c() {
       2.579 us [ 1892] |         getpid();
       3.739 us [ 1892] |       } /* c */
       4.376 us [ 1892] |     } /* b */
       4.962 us [ 1892] |   } /* a */
       5.769 us [ 1892] | } /* main */

더 상세한 분석을 하려면, record를 통해 우선 데이터를 기록하고
replay, report, graph, dump, info와 같은 분석 명령어를 여러 번
사용하는 것이 좋다.

    $ uftrace record tests/t-abc

record 명령어는 추적 데이터 파일을 포함하는 uftrace.data 디렉터리를 만든다.
다른 분석 명령어들은 그 디렉터리가 현재 경로에 있을 것으로 예상하지만,
다른 디렉터리를 쓰기 위해서는 `-d` 옵션을 사용하면 된다.

`replay` 명령어는 위 실행 결과를 보여준다. 보다시피, t-abc는
그저 a, b, c 함수를 호출하는 단순한 프로그램이다.
C 함수에서, 일반적인 시스템의 C 라이브러리 (glibc)에 내장된 라이브러리
함수 getpid()를 호출한다. (__cxa_atexit()도 마찬가지 경우이다.)

사용자들은 함수들의 레코드/출력을 제한하기 위해 다양한 필터를 이용할 수 있다.
깊이 필터 (`-D` 옵션)는 주어진 호출 깊이보다 더 깊게 호출된 함수들을 생략하는 필터이다.
시간 필터 (`-t` 옵션)는 주어진 시간보다 더 작은 시간동안 실행된 함수들을 생략하는 필터이다.
함수 필터 (`-F`와 `-N` 옵션)는 주어진 함수의 하위 함수들을 보여주고/생략하는 필터이다.

`-k` 옵션으로 커널 함수들 또한 추적이 가능하다 (루트 권한 필요).
보통 'hello world' 프로그램에 대한 출력 결과는 아래와 같다.
(시스템 콜을 직접 호출하기 위해, 일반적인 printf()가 아닌 stderr와
fprintf()를 사용하기로 한 것에 유의하라):

    $ sudo uftrace -k tests/t-hello
    Hello world
    # DURATION    TID     FUNCTION
       1.365 us [21901] | __monstartup();
       0.951 us [21901] | __cxa_atexit();
                [21901] | main() {
                [21901] |   fprintf() {
       3.569 us [21901] |     __do_page_fault();
      10.127 us [21901] |     sys_write();
      20.103 us [21901] |   } /* fprintf */
      21.286 us [21901] | } /* main */

fprintf()호출 내부에서 page fault 핸들러와 write syscall 핸들러가
호출되었음을 확인할 수 있다.

또한 함수의 인자와 반환 값을 각각 `-A`와 `-R`옵션으로 기록하고 보여줄 수 있다.
이하 예제에서는 'fib'(피보나치 숫자) 함수의 첫 번째 인자와 리턴값을 기록한다.

    $ uftrace record -A fib@arg1 -R fib@retval tests/t-fibonacci 5

    $ uftrace replay
    # DURATION    TID     FUNCTION
       2.853 us [22080] | __monstartup();
       2.194 us [22080] | __cxa_atexit();
                [22080] | main() {
       2.706 us [22080] |   atoi();
                [22080] |   fib(5) {
                [22080] |     fib(4) {
                [22080] |       fib(3) {
       7.473 us [22080] |         fib(2) = 1;
       0.419 us [22080] |         fib(1) = 1;
      11.452 us [22080] |       } = 2; /* fib */
       0.460 us [22080] |       fib(2) = 1;
      13.823 us [22080] |     } = 3; /* fib */
                [22080] |     fib(3) {
       0.424 us [22080] |       fib(2) = 1;
       0.437 us [22080] |       fib(1) = 1;
       2.860 us [22080] |     } = 2; /* fib */
      19.600 us [22080] |   } = 5; /* fib */
      25.024 us [22080] | } /* main */

`report` 명령어는 어떤 함수가 그 자식 함수를 포함해서 가장 오랫동안
실행되었는지(총시간)를 알려준다.

    $ uftrace report
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================================
       25.024 us    2.718 us           1  main
       19.600 us   19.600 us           9  fib
        2.853 us    2.853 us           1  __monstartup
        2.706 us    2.706 us           1  atoi
        2.194 us    2.194 us           1  __cxa_atexit


`graph` 명령어는 주어진 함수의 호출 그래프를 보여준다.
위의 예제에서, main 함수의 호출 그래프는 아래와 같다:

    $ uftrace graph  main
    # Function Call Graph for 'main' (session: 073f1e84aa8b09d3)
    =============== BACKTRACE ===============
     backtrace #0: hit 1, time  25.024 us
       [0] main (0x40066b)

    ========== FUNCTION CALL GRAPH ==========
      25.024 us : (1) main
       2.706 us :  +-(1) atoi
                :  |
      19.600 us :  +-(1) fib
      16.683 us :    (2) fib
      12.773 us :    (4) fib
       7.892 us :    (2) fib


`dump` 명령은 기록된 데이터를 그대로(raw) 출력하여 보여준다.
`uftrace dump --chrome` 명령을 사용하면 크롬 브라우저에서 결과를 확인할 수 있다.
이하는 작은 C++ template metaprogram을 컴파일하는 clang (LLVM)의 실행 과정을 보여준다.

[![uftrace-chrome-dump](../uftrace-chrome.png)](https://uftrace.github.io/dump/clang.tmp.fib.html)

flame-graph 형식의 결과 또한 지원한다. 해당 데이터는 `uftrace dump --flame-graph`로 실행되어
[flamegraph.pl](https://github.com/brendangregg/FlameGraph/blob/master/flamegraph.pl)로 넘겨질 수 있다.
이하는 간단한 C 프로그램을 gcc로 컴파일한 결과에 대한 flame graph이다.

[![uftrace-flame-graph-dump](https://uftrace.github.io/dump/gcc.svg)](https://uftrace.github.io/dump/gcc.svg)

`info` 명령어는 기록이 되었을 때의 시스템과 프로그램 정보를 보여준다.

    $ uftrace info
    # system information
    # ==================
    # program version     : uftrace v0.8.1
    # recorded on         : Tue May 24 11:21:59 2016
    # cmdline             : uftrace record tests/t-abc
    # cpu info            : Intel(R) Core(TM) i7-3930K CPU @ 3.20GHz
    # number of cpus      : 12 / 12 (online / possible)
    # memory info         : 20.1 / 23.5 GB (free / total)
    # system load         : 0.00 / 0.06 / 0.06 (1 / 5 / 15 min)
    # kernel version      : Linux 4.5.4-1-ARCH
    # hostname            : sejong
    # distro              : "Arch Linux"
    #
    # process information
    # ===================
    # number of tasks     : 1
    # task list           : 5098
    # exe image           : /home/namhyung/project/uftrace/tests/t-abc
    # build id            : a3c50d25f7dd98dab68e94ef0f215edb06e98434
    # exit status         : exited with code: 0
    # elapsed time        : 0.003219479 sec
    # cpu time            : 0.000 / 0.003 sec (sys / user)
    # context switch      : 1 / 1 (voluntary / involuntary)
    # max rss             : 3072 KB
    # page fault          : 0 / 172 (major / minor)
    # disk iops           : 0 / 24 (read / write)

`script` 명령어는 기록된 데이터에 사용자 정의 스크립트를 실행할 수 있게 한다.
현재까지 지원되는 스크립트는 Python 3, Python 2.7 과 Lua 5.1 이다.

`tui` 명령어는 ncurses 를 이용한 텍스트 기반 대화형 사용자 인터페이스를 위한 명령어이다.
현재 `graph`, `report`, `info` 명령어의 기본적인 기능을 제공한다.


제약사항
===========
- 리눅스와 안드로이드에서 실행되는 C/C++/Rust/Python 애플리케이션에
  대해서만 사용 가능하다.
- 이미 실행 중인 프로세스의 추적은 아직 *불가능*하다.
- 전체 시스템에 대한 통합 분석은 *불가능*하다.
- 현재는 x86_64, AArch64 만 지원한다. x86 (32-bit),
  ARM (v6, v7) 환경에서도 작동하지만, 동적 추적이나 자동 인자 가져오기와
  같은 일부 기능은 잘 작동하지 않을 수 있다.


라이선스
=======
uftrace 는 GPL v2. 라이선스 하에 배포되며 자세한 내용은 [COPYING](../../COPYING) 파일에서 확인할 수 있다.
