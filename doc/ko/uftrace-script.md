% UFTRACE-SCRIPT(1) Uftrace User Manuals
% Honggyu Kim <honggyu.kp@gmail.com>, Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace-script - 기록된 데이터를 대상으로 스크립트를 실행한다.


사용법
======
uftrace script (-S|--script) <script file> [*options*]
uftrace script (-S|--script) <script file> [*options*] --record COMMAND


설명
====
이 명령어는 `uftrace-record`(1) 명령어를 통해 기록된 데이터를 대상으로 스크립트를 실행한다.


SCRIPT 옵션
============
-S *SCRIPT_PATH*, \--script=*SCRIPT_PATH*
:   기록된 추적 데이터를 수행하는 동안 주어진 스크립트가 함수의 시작과 끝에서 추가적인
    작업을 하도록 한다.
    파일의 확장자에 따라 스크립트 타입이 감지된다.
    예를 들어 '.py'의 경우에는 파이썬, '.lua'의 경우 lua 5.1 스크립트로서 감지된다.
    *SCRIPT 실행*을 보라.

\--record COMMAND [*command-options*]
:   주어진 스크립트로 실행하기 전에 새로운 추적을 기록한다.
    현재 지원되는 스크립트 타입으로는 Python 2.7과 Lua 5.1이 있다


공통 옵션
==============
-F *FUNC*, \--filter=*FUNC*
:   선택된 함수들 (그리고 그 내부의 함수들)만 스크립트를 실행하도록 필터를
    설정한다.  이 옵션은 한번 이상 쓰일 수 있다.
    필터에 대한 설명은 `uftrace-replay` 를 참고한다.

-N *FUNC*, \--notrace=*FUNC*
:   선택된 함수들 (또는 그 아래 함수들)을 스크립트 실행에서 제외하도록 설정하는
    옵션이다.  이 옵션은 한번 이상 쓰일 수 있다.
    필터에 대한 설명은 `uftrace-replay` 를 참고한다.

-H *FUNC*, \--hide=*FUNC*
:   주어진 FUNC 함수들을 출력 대상에서 제외할 수 있다.  이는 선택된 함수의 자식
    함수들에 대해서는 영향을 주지 않으며 단지 주어진 함수들만 숨기는 기능을 하게
    된다. 이 옵션은 한번 이상 쓰일 수 있다.

-C *FUNC*, \--caller-filter=*FUNC*
:   선택된 함수의 호출자에 대해 스크립트를 실행하는 필터를 설정한다.
    이 옵션은 한번 이상 쓰일 수 있다.
    필터에 대한 설명은 `uftrace-replay` 를 참고한다.

-T *TRG*, \--trigger=*TRG*
:   선택된 함수의 트리거를 설정한다. 이 옵션은 한번 이상 쓰일 수 있다.
    트리거에 대한 설명은 `uftrace-replay` 를 참고한다.

-D *DEPTH*, \--depth=*DEPTH*
:   함수가 중첩될 수 있는 최대 깊이를 설정한다.

-t *TIME*, \--time-filter=*TIME*
:   설정한 시간 이하로 수행된 함수는 스크립트를 실행하지 않게 한다. 만약 어떤
    함수가 명시적으로 'trace' 트리거가 적용된 경우, 그 함수는 실행 시간과
    상관없이 항상 스크립트를 실행한다.

\--no-libcall
:   라이브러리 호출은 스크립트를 실행하지 않게 한다.

\--match=*TYPE*
:   TYPE으로 일치하는 패턴을 보여준다. 가능한 형태는 `regex`와 `glob`이다.
    기본은 `regex`이다.


공통 분석 옵션
=============
\--kernel-full
:   사용자 함수 밖에서 호출된 모든 커널 함수에 대하여 스크립트를 실행한다.

\--kernel-only
:   사용자 함수를 제외한 커널 함수에 대해서만 스크립트를 실행한다.

\--tid=*TID*[,*TID*,...]
:   주어진 태스크에 의해 호출된 함수만 스크립트를 실행한다.
    uftrace report --task 또는 uftrace info 를 이용해 데이터 파일 내의 태스크
    목록을 볼 수 있다.  이 옵션은 한번 이상 쓰일 수 있다.

\--demangle=*TYPE*
:   필터, 트리거, 함수인자와 (또는) 반환 값을 디맹글(demangled)된 C++ 심볼 이름으로 사용한다.
    "full", "simple" 그리고 "no" 값을 사용할 수 있다.
    함수인자와 템플릿 파라미터를 무시하는 "simple"이 기본이다.

-r *RANGE*, \--time-range=*RANGE*
:   시간 RANGE 내에 수행된 함수들만 스크립트를 실행한다. RANGE는 \<시작\>~\<끝\>
    ("~" 로 구분) 이고 \<시작\>과 \<끝\> 중 하나는 생략 될 수 있다.
    \<시작\>과 \<끝\> 은 타임스탬프 또는 '100us'와 같은 \<시간단위\>가 있는
    경과 시간이다.
    `uftrace replay`(1)에서 `-f time` 또는 `-f elapsed`를 이용해 타임스탬프 또는
    경과 시간을 표시할 수 있다.


SCRIPT EXECUTION
================
uftrace 는 함수의 진입과 반환 시점에 스크립트 실행이 가능하다.
현재 지원되는 스크립트 타입은 Python 2.7, Python 3 그리고 Lua 5.1 이다.

사용자는 네 개의 함수를 작성할 수 있다. 'uftrace_entry' 와 'uftracce_exit' 은
각 함수의 진입시점과 반환시점에 항상 실행된다.  하지만 'uftrace_begin' 과
'uftrace_end' 는 분석 대상 프로그램이 초기화되고 종료될때 한 번씩만 실행된다.

    $ cat scripts/simple.py
    def uftrace_begin(ctx):
        print("program begins...")

    def uftrace_entry(ctx):
        func = ctx["name"]
        print("entry : " + func + "()")

    def uftrace_exit(ctx):
        func = ctx["name"]
        print("exit  : " + func + "()")

    def uftrace_end():
        print("program is finished")

'ctx' 변수는 아래의 정보를 포함하는 사전타입(dictionary type)의 변수이다.

    /* context information passed to uftrace_entry(ctx) and uftrace_exit(ctx) */
    script_context = {
        int       tid;
        int       depth;
        long      timestamp;
        long      duration;    # exit only
        long      address;
        string    name;
        list      args;        # entry only (if available)
        value     retval;      # exit  only (if available)
    };

    /* context information passed to uftrace_begin(ctx) */
    script_context = {
        bool      record;      # True if it runs at record time, otherwise False
        string    version;     # uftrace version info
        list      cmds;        # execution commands
    };

위의 스크립트는 미리 기록되어 있는 uftrace 데이터를 대상으로 실행될수 있다.
사용법은 다음과 같다.

    $ uftrace record -F main tests/t-abc

    $ uftrace script -S scripts/simple.py
    program begins...
    entry : main()
    entry : a()
    entry : b()
    entry : c()
    entry : getpid()
    exit  : getpid()
    exit  : c()
    exit  : b()
    exit  : a()
    exit  : main()
    program is finished

아래는 같은 데이터에 대하여 이전의 예와 다른 결과를 출력하는 예제이다.
결과는 `uftrace replay` 와 비슷한 모습을 가진다.

    $ uftrace script -S scripts/replay.py
    # DURATION    TID     FUNCTION
                [25794] | main() {
                [25794] |   a() {
                [25794] |     b() {
                [25794] |       c() {
                [25794] |         getpid() {
      11.037 us [25794] |         } /* getpid */
      44.752 us [25794] |       } /* c */
      70.924 us [25794] |     } /* b */
      98.191 us [25794] |   } /* a */
     124.329 us [25794] | } /* main */

위의 파이썬 스크립트는 결과를 원하는 방식으로 출력하기 위해 수정될 수 있다.

스크립트는 스크립트를 실행하는 함수의 이름(또는 --match 옵션에 따른 패턴)의
"UFTRACE_FUNCS" 리스트를 선택적으로 가질 수 있는데 만약 이 리스트가 존재하면,
이름이나 패턴이 일치하는 함수들만 스크립트를 실행한다.
예를 들어, 다음과 같은 한 줄을 스크립트에 추가했다면, 이름이 한 글자인 함수들만
스크립트를 실행한다.

    $ echo 'UFTRACE_FUNCS = [ "^.$" ]' >> replay.py
    $ uftrace script -S replay.py
    # DURATION    TID     FUNCTION
                [25794] |   a() {
                [25794] |     b() {
                [25794] |       c() {
      44.752 us [25794] |       } /* c */
      70.924 us [25794] |     } /* b */
      98.191 us [25794] |   } /* a */

또한, 스크립트는 자체적으로 데이터를 기록(record)하는 과정에 함수의 인자 또는
반환 값과 같은 정보를 위한 옵션을 내부적으로 가질 수 있다.
"uftrace-option:" 으로 시작하는 주석이 있으면 기록하는 동안 필요한 uftrace 의
record 옵션들을 자동으로 추가할 수 있다.

    $ cat arg.py
    #
    # uftrace-option: -A a@arg1 -R b@retval
    #
    def uftrace_entry(ctx):
        if "args" in ctx:
            print(ctx["name"] + " has args")
    def uftrace_exit(ctx):
        if "retval" in ctx:
            print(ctx["name"] + " has retval")

    $ uftrace record -S arg.py abc
    a has args
    b has retval
    $ uftrace script -S arg.py
    a has args
    b has retval


함께 보기
=========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-live`(1)


번역자
======
조정근 <wjdrms1388@gmail.com>, 김홍규 <honggyu.kp@gmail.com>
