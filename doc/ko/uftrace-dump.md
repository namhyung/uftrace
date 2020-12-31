% UFTRACE-DUMP(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace-dump - 기록된 데이터를 다양한 형식으로 출력한다.


사용법
======
uftrace dump [*options*]


설명
====
데이터 파일에 기록된 데이터를 보여주는 명령어이다. 출력 형식은
--chrome, --flame-graph 또는 --graphviz 와 같은 옵션으로 설정할 수 있다.


DUMP 옵션
=========
\--chrome
:   구글 크롬 추적 기능에서 사용되는 JSON 형식의 결과물을 표시한다.

\--flame-graph
:   최신 웹 브라우저에서 볼 수 있는 FlameGraph 형식으로 표시한다.
    (FlameGraph 툴로 처리 필요)

\--graphviz
:   Graphviz 툴킷에서 사용되는 DOT 형식의 결과물을 표시한다.

\--debug
:   16진수 데이터를 보여준다.

\--sample-time=*시간*
:   --flame-graph 옵션의 결과물을 생성할 때 샘플링 시간을 적용한다. 기본으로는
    각 함수의 호출 수가 적용된다. 이 옵션이 사용되면 주어진 단위로 실행 시간을
    계산하여 샘플링한다. 만약 주어진 샘플링 시간보다 적게 수행된 함수는 결과물
    에서 제외되지만, 더 길게 수행된 함수는 표시된다.


공통 옵션
=========
-F *FUNC*, \--filter=*FUNC*
:   선택된 함수들(그리고 그 내부의 함수들)만 출력하도록 필터를 설정한다.
    이 옵션은 한번 이상 쓰일 수 있다. 필터에 대한 설명은 `uftrace-replay`(1) 를
    참고한다.

-N *FUNC*, \--notrace=*FUNC*
:   선택된 함수들 (또는 그 아래 함수들)을 출력에서 제외하도록 설정하는 옵션이다.
    이 옵션은 한번 이상 쓰일 수 있다. 필터에 대한 설명은 `uftrace-replay`(1) 를
    참고한다.

-H *FUNC*, \--hide=*FUNC*
:   주어진 FUNC 함수들을 출력 대상에서 제외할 수 있다.  이는 선택된 함수의 자식
    함수들에 대해서는 영향을 주지 않으며 단지 주어진 함수들만 숨기는 기능을 하게
    된다. 이 옵션은 한번 이상 쓰일 수 있다.

-C *FUNC*, \--caller-filter=*FUNC*
:   선택된 함수의 호출자를 출력하는 필터를 설정한다. 이 옵션은 한번 이상 쓰일 수 있다.
    필터에 대한 설명은 `uftrace-replay`(1) 를 참고한다.

-T *TRG*, \--trigger=*TRG*
:   선택된 함수의 트리거를 설정한다. 이 옵션은 한번 이상 쓰일 수 있다.
    트리거에 대한 설명은 `uftrace-replay`(1) 를 참고한다.

-D *DEPTH*, \--depth *DEPTH*
:   함수가 중첩될 수 있는 최대 깊이를 설정한다.
    (이를 넘어서는 상세한 함수 실행과정은 무시한다.)

-t *TIME*, \--time-filter=*TIME*
:   설정한 시간 이하로 수행된 함수는 표시하지 않게 한다. 만약 어떤 함수가
    명시적으로 'trace' 트리거가 적용된 경우, 그 함수는 실행 시간과 상관없이 항상
    출력된다.

\--no-libcall
:   라이브러리 호출은 표시하지 않게 한다.

\--no-event
:   이벤트는 표시하지 않게 한다.

\--match=*TYPE*
:   타입(TYPE)으로 일치하는 패턴을 보여준다. 가능한 형태는 `regex`와 `glob`이다.
    기본 설정은 `regex`이다.


공통 분석 옵션
=======================
\--kernel-full
:   사용자 함수 밖에서 호출된 모든 커널 함수를 출력한다.
    이 옵션은 --chrome, --flame-graph 또는 --graphviz 옵션과 함께 사용될 때만
    의미가 있다.

\--kernel-only
:   사용자 함수를 제외한 커널 함수만 출력한다.

\--event-full
:   사용자 함수 밖의 모든 (사용자) 이벤트를 출력한다.
    이 옵션은 --chrome, --flame-graph 또는 --graphviz 옵션과 함께 사용될 때만
    의미가 있다.

\--tid=*TID*[,*TID*,...]
:   주어진 태스크에 의해 호출된 함수들만 출력한다. `uftrace report --task`
    또는 `uftrace info` 를 이용해 데이터 파일 내의 태스크 목록을 볼 수 있다.
    이 옵션은 한번 이상 쓰일 수 있다.

\--demangle=*TYPE*
:   필터, 트리거, 함수인자와 (또는) 반환 값을 디맹글(demangle)된 C++ 심볼
    이름으로 사용한다. "full", "simple", "no" 값을 사용할 수 있다.
    기본 설정은 "simple"이며, 템플릿 파라미터와 함수 인자를 무시한다.

-r *RANGE*, \--time-range=*RANGE*
:   시간 범위 RANGE 내에 실행된 함수들만 출력한다. RANGE 는 \<시작\>~\<끝\>
    ("~"로 구분) 이고 \<시작\>과 \<끝\> 중 하나는 생략할 수 있다. \<시작\>과
    \<끝\>은 타임스탬프 또는 '100us'와 같은 \<시간단위\>가 있는 경과시간이다.
    `uftrace replay`(1) 에서 `-f time` 또는 `-f elapsed` 를 이용해 타임스탬프
    또는 경과시간을 확인할 수 있다.


예제
====
이 명령어는 아래와 같은 결과를 출력한다.

    $ uftrace record abc

    $ uftrace dump
    uftrace file header: magic         = 4674726163652100
    uftrace file header: version       = 4
    uftrace file header: header size   = 40
    uftrace file header: endian        = 1 (little)
    uftrace file header: class         = 2 (64 bit)
    uftrace file header: features      = 0x63 (PLTHOOK | TASK_SESSION | SYM_REL_ADDR | MAX_STACK)
    uftrace file header: info          = 0x3ff

    reading 23043.dat
    105430.415350255  23043: [entry] __monstartup(4004d0) depth: 0
    105430.415351178  23043: [exit ] __monstartup(4004d0) depth: 0
    105430.415351932  23043: [entry] __cxa_atexit(4004f0) depth: 0
    105430.415352687  23043: [exit ] __cxa_atexit(4004f0) depth: 0
    105430.415353833  23043: [entry] main(400512) depth: 0
    105430.415353992  23043: [entry] a(4006b2) depth: 1
    105430.415354112  23043: [entry] b(4006a0) depth: 2
    105430.415354230  23043: [entry] c(400686) depth: 3
    105430.415354425  23043: [entry] getpid(4004b0) depth: 4
    105430.415355035  23043: [exit ] getpid(4004b0) depth: 4
    105430.415355549  23043: [exit ] c(400686) depth: 3
    105430.415355761  23043: [exit ] b(4006a0) depth: 2
    105430.415355943  23043: [exit ] a(4006b2) depth: 1
    105430.415356109  23043: [exit ] main(400512) depth: 0

    $ uftrace dump --chrome -F main
    {"traceEvents":[
    {"ts":105430415353,"ph":"B","pid":23043,"name":"main"},
    {"ts":105430415353,"ph":"B","pid":23043,"name":"a"},
    {"ts":105430415354,"ph":"B","pid":23043,"name":"b"},
    {"ts":105430415354,"ph":"B","pid":23043,"name":"c"},
    {"ts":105430415354,"ph":"B","pid":23043,"name":"getpid"},
    {"ts":105430415355,"ph":"E","pid":23043,"name":"getpid"},
    {"ts":105430415355,"ph":"E","pid":23043,"name":"c"},
    {"ts":105430415355,"ph":"E","pid":23043,"name":"b"},
    {"ts":105430415355,"ph":"E","pid":23043,"name":"a"},
    {"ts":105430415356,"ph":"E","pid":23043,"name":"main"}
    ], "metadata": {
    "command_line":"uftrace record abc ",
    "recorded_time":"Tue May 24 19:44:54 2016"
    } }

    $ uftrace dump --flame-graph --sample-time 1us
    main 1
    main;a;b;c 1

    $ uftrace dump --graphviz
    \# command_line "uftrace record tests/t-abc"
    digraph "/home/m/git/uftrace/tests/t-abc" {
            \# Attributes
            splines=ortho;
            concentrate=true;
            node [shape="rect",fontsize="7",style="filled"];
            edge [fontsize="7"];
            \# Elements
            main[xlabel = "Calls : 1"]
            main->a[xlabel = "Calls : 1"]
            a->b[xlabel = "Calls : 1"]
            b->c[xlabel = "Calls : 1"]
            c->getpid[xlabel = "Calls : 1"]
    }

함께 보기
=========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1)


번역자
======
민지수 <kuongee@gmail.com>
