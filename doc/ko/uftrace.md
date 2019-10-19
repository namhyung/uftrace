% UFTRACE(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace - 프로그램 함수 호출 분석 도구


사용법
======
uftrace [*record*|*replay*|*live*|*report*|*info*|*dump*|*recv*|*graph*|*script*|*tui*] [*options*] COMMAND [*command-options*]


설명
====
uftrace 는 `COMMAND` 에 주어지는 프로그램의 실행을 함수 단위로 추적(trace)하는
분석 도구이다.  `COMMAND` 에 주어지는 프로그램은 `-pg` 또는 `-finstrument-function`
로 컴파일된 C 또는 C++ 프로그램이다.
COMMAND 의 대상이 되는 실행 이미지는 이름을 읽을 수 있도록 (스트립 되지 않은)
ELF 심볼 테이블을 필요로 한다.

uftrace 는 `git`(1) 또는 `perf`(1) 와 같은 방식으로 다수의 보조 명령어들을 갖는다.
아래에 보조 명령어과 함께 간략한 설명이 있다.  더 자세한 정보를 위해서는 각 보조
명령어들의 메뉴얼 페이지를 참조할 수 있다.  또한, 이 페이지에 있는 옵션들은 다른
보조 명령어들과 함께 사용될 수 있다.

만약 보조 명령어를 명시적으로 입력하지 않으면, uftrace 는 record 와 replay 를
한번에 수행하는 `live` 보조 명령어로 동작한다.
live 명령어의 옵션들은 `uftrace-live`(1) 에서 참조할 수 있다.
더 자세한 분석을 위해, `uftrace-record`(1) 를 통해 데이터를 기록하고,
`uftrace-replay`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-dump`(1),
`uftrace-script`(1), `uftrace-tui`(1) 중에 하나를 사용하여 분석할 수 있다.


보조 명령어
============
record
:   명령어를 실행하고 데이터를 파일이나 디렉터리에 저장한다.

replay
:   저장된 함수를 시간정보와 함께 출력한다.

live
:   실시간 추적을 하고, 실행되는 함수를 출력한다.

report
:   다양한 통계와 저장된 데이터를 요약하여 출력한다.

info
:   OS 버전, cpu 정보, 라인 수 등의 추가적인 정보를 출력한다.

dump
:   데이터 파일에 있는 저수준 데이터를 출력한다.

recv
:   네트워크로 보내진 데이터를 저장한다.

graph
:   함수 호출 그래프를 출력한다.

script
:   저장된 함수 스크립트를 실행한다.

tui
:   graph 와 report 를 볼 수 있는 텍스트 형식의 사용자 인터페이스를 보여준다.


옵션
====
-?, \--help
:   사용법을 옵션 리스트로 설명과 함께 출력한다.

-h, \--help
:   사용법을 옵션 리스트로 설명과 함께 출력한다.

\--usage
:   사용법을 문자열로 출력한다.

-V, \--version
:   프로그램의 버전을 출력한다.

-v, \--verbose
:   세부적인 메시지를 출력한다. 이 옵션은 디버그 레벨을 3 까지 올릴 수 있다.

\--debug
:   디버그 메시지를 출력한다. 이 옵션은 `-v'/ `--verbose`와 같으며 하위 호환성을
    위해서만 존재한다.

\--debug-domain=*DOMAIN*[,*DOMAIN*, ...]
:   디버그 메시지출력을 도메인으로 한정한다. 가능한 도메인들은 uftrace, symbol,
    demangle, filter, fstack, session, kernel, mcount, dynamic, event, script
    그리고 dwarf 가 있다.
    위의 도메인들은 콜론을 이용해 선택적으로 각각의 도메인 레벨을 지정할 수 있다.
    예를 들어, `-v --debug-domain=filter:2` 는 filter 옵션에 디버깅 레벨을 지정하고,
    다른 도메인은 디버그 레벨을 1 로 지정한다.

-d *DATA*, \--data=*DATA*
:   데이터를 저장할 디렉터리의 이름을 정한다. 기본값은 `uftrace.data` 이다.

\--logfile=*FILE*
:   경고와 디버그 메시지를 stderr 을 대신해 *FILE* 안에 저장한다.

\--color=*VAL*
:   결과에 색을 지정하거나 지정하지 않는다. 가능한 값은
    "yes"(= "true" | "1" | "on" ), "no"(= "false" | "0" | "off" ) 와 "auto" 이다.
    "auto" 는 출력이 터미널인 경우 기본적으로 색을 지정한다.

\--no-pager
:   pager 기능을 사용하지 않는다.

\--opt-file=*FILE*
:   uftrace 실행에 사용하는 옵션을 파일에서 읽어서 적용한다.


함께 보기
========
`uftrace-live`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-dump`(1), `uftrace-recv`(1), `uftrace-graph`(1), `uftrace-script`(1), `uftrace-tui(1)`


번역자
======
류준호 <ruujoon93@gmail.com>
