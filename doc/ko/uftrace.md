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
로 컴파일된 C 또는 C++ 프로그램이어야 한다.
COMMAND 의 대상이 되는 실행 이미지는 이름을 읽을 수 있도록
(i.e `strip`(1) 되어 있지 않은) ELF 심볼 테이블을 필요로 한다.

uftrace 는 `git`(1) 또는 `perf`(1) 와 같은 방식으로 다수의 보조 명령어들을 갖는다.
아래에 보조 명령어과 함께 간략한 설명이 있다.  더 자세한 정보를 위해서는 각 보조
명령어들의 메뉴얼 페이지를 참조할 수 있다.  또한, 이 페이지에 있는 옵션들은 다른
보조 명령어들과 함께 사용될 수 있다.

만약 보조 명령어를 명시적으로 입력하지 않으면, uftrace 는 `record` 와 `replay` 를
한번에 수행하는 `live` 보조 명령어로 동작한다.
live 명령어의 옵션들은 `uftrace-live`(1) 에서 참조할 수 있다.
더 자세한 분석을 위해, `uftrace-record`(1) 를 통해 데이터를 기록하고,
`uftrace-replay`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-dump`(1),
`uftrace-script`(1), `uftrace-tui`(1) 중 하나를 사용하여 분석할 수 있다.


보조 명령어
============
record
:   주어진 명령어를 실행하고 데이터를 파일이나 디렉터리에 저장한다.

replay
:   저장된 함수를 시간 정보와 함께 출력한다.

live
:   실시간 추적을 진행하고, 실행되는 함수를 출력한다.

report
:   다양한 통계와 저장된 데이터를 요약하여 출력한다.

info
:   OS 버전, CPU 정보, 라인 수 등의 추가적인 정보를 출력한다.

dump
:   데이터 파일에 있는 저수준 데이터를 출력한다.

recv
:   네트워크로부터 전달받은 데이터를 저장한다.

graph
:   함수 호출 그래프를 출력한다.

script
:   저장된 함수 추적 데이터와 관련된 스크립트를 실행한다.

tui
:   graph 와 report 를 볼 수 있는 텍스트 형식의 사용자 인터페이스를 보여준다.


옵션
====
-h, \--help
:   사용법을 옵션 리스트로 설명과 함께 출력한다.

\--usage
:   사용법을 문자열로 출력한다.

-V, \--version
:   프로그램의 버전을 출력한다.

-v, \--verbose
:   세부적인 메시지를 출력한다.  이 옵션은 디버그 레벨을 3 까지 올릴 수 있다.

\--debug
:   디버그 메시지를 출력한다.  이 옵션은 `-v`/`--verbose` 와 같으며 하위 호환성을
    위해서만 존재한다.

\--debug-domain=*DOMAIN*[,*DOMAIN*, ...]
:   디버그 메시지 출력을 도메인으로 한정한다. 가능한 도메인들은 uftrace, symbol,
    demangle, filter, fstack, session, kernel, mcount, dynamic, event, script
    그리고 dwarf 가 있다.
    위의 도메인들은 콜론을 이용해 선택적으로 각각의 도메인 레벨을 지정할 수 있다.
    예를 들어, `-v --debug-domain=filter:2` 는 filter 옵션에 디버깅 레벨을 지정하고,
    다른 도메인은 디버그 레벨을 1로 지정한다.

-d *DATA*, \--data=*DATA*
:   데이터를 저장할 디렉터리의 이름을 정한다.  기본값은 `uftrace.data` 이다.

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


보조 명령별 옵션
================
이 옵션들은 완전성을 위해 여기에 존재하지만, 특정 보조 명령어에서만
유효하다.

uftrace-<*subcommand*> 메뉴얼 페이지에서 추가적인 정보를 확인할 수 있다.
*uftrace-live*(1) 메뉴얼 페이지는 특이한 페이지이다: 보조 멍령어 `live` 는
`record` 와 `replay` 의 기능을 내부적으로 진행한다.  그러므로,


\--avg-self
:   각 함수의 자체 시간(self time)의 평균, 최소, 최대 시간을 보여준다.

\--avg-total
:   각 함수의 총 시간(total time)의 평균, 최소, 최대 시간을 보여준다.

-a, \--auto-args
:   알려진 함수의 인자와 반환값들을 자동으로 기록한다.

-A, \--argument=*FUNC*@arg[,arg,...]
:   함수 인자를 표시한다.

-b, \--buffer=*SIZE*
:   저장할 데이터의 내부 버퍼 크기를 설정한다. (기본값: 128k)

\--chrome
:   구글 크롬 추적 기능에서 사용되는 JSON 형식의 결과물을 표시한다.

\--clock
:   타임스탬프를 읽는 클럭 소스를 설정한다. (기본값: mono)

\--column-offset=*DEPTH*
:   각 열의 간격(offset) 크기를 명시한다. (기본값: 8)

\--column-view
:   열(column) 별로 분리하여 각각의 태스크를 출력한다.

-C, \--caller-filter=*FUNC*
:   FUNC의 호출자를 출력하는 필터를 설정한다.

\--demangle=*TYPE*
:   C++ 심볼 디맹글링: full, simple, no
:   (기본값: simple)

\--diff=*DATA*
:   차이점을 보고한다.

\--diff-policy=*POLICY*
:   diff 보고 정책을 설정한다.
:   (기본값: 'abs,compact,no-percent')

\--disable
:   데이터를 기록하지 않고 시작한다.

-D, \--depth=*DEPTH*
:   *DEPTH* 깊이만큼 함수를 추적한다.

-e, \--estimate-return
:   안정성을 위해 각 함수의 진입 데이터만을 기록한다.

\--event-full
:   사용자 함수 밖의 모든 이벤트를 출력한다.

-E, \--Event=*EVENT*
:   더 많은 정보를 저장하기 위해 *EVENT* 를 활성화한다.

\--flame-graph
:   기록된 데이터를 FlameGraph 형식으로 표시한다.

\--flat
:   평평한(flat) 형식으로 출력한다.

\--force
:   계측 정보가 없는 실행 파일이여도 추적한다.

\--format=*FORMAT*
:   *FORMAT* 으로 형식화된 출력을 보여준다: normal, html (기본값: normal)

-f, \--output-fields=*FIELD*
:   replay 혹은 graph 출력에서 FIELD를 보여준다.

-F, \--filter=*FUNC*
:   FUNC 만 추적한다.

-g, \--agent
:   명령어를 받기 위해 mcount에서 에이전트를 시작한다.

\--graphviz
:   기록된 데이터를 *DOT* 형식으로 덤프한다.

-H, \--hide=*FUNC*
:   추적에서 FUNC 를 숨긴다.

\--host=*HOST*
:   추적 데이터를 파일에 쓰는 대신 *HOST* 에 전달한다.

-k, \--kernel
:   지원하는 경우, 커널 함수 또한 추적한다.

\--keep-pid
:   프로그램을 추적할 때 동일한 pid 값을 유지하게 해준다.

\--kernel-buffer=*SIZE*
:   저장할 커널 데이터의 내부 버퍼 크기를 설정한다.  (기본값: 1408K)

\--kernel-full
:   사용자 함수 밖에서 호출된 모든 커널 함수를 출력한다.

\--kernel-only
:   사용자 함수를 제외한 커널 함수만 출력한다.

\--kernel-skip-out
:   사용자 함수 밖의 커널 함수를 생략한다. (지원 종료)

-K, \--kernel-depth=*DEPTH*
:   커널 최대 함수 깊이를 *DEPTH* 로 지정한다.

\--libmcount-single
:   libmcount 의 단일 쓰레드 버전을 사용한다.

\--list-event
:   실행중에 사용가능한 이벤트들을 출력한다.

\--logfile=*FILE*
:   경고와 디버그 메시지를 stderr 을 대신해 *FILE* 안에 저장한다.

-l, \--nest-libcall
:   중첩된 라이브러리 호출을 보여준다.

\--libname
:   함수 이름과 함께 라이브러리 이름을 출력한다

\--libmcount-path=*PATH*
:   libmcount 라이브러리를 *PATH* 에서 먼저 찾는다.
:   Load libmcount libraries from this *PATH*

\--match=*TYPE*
:   일치하는 패턴을 보여준다: regex, glob (기본값:
:   regex)

\--max-stack=*DEPTH*
:   스택의 최대 깊이를 *DEPTH* 로 설정한다. (기본값: 65535)

\--no-args
:   함수 인자와 반환 값을 보여주지 않는다.

\--no-comment
:   함수가 반환되는 곳에 주석을 출력하지 않는다.

\--no-event
:   기본 이벤트들을 비활성화한다.

\--no-sched
:   스케줄 이벤트를 비활성화한다.

\--no-sched-preempt
:   선점 스케줄 이벤트는 표시하지 않게 하나
:   일반(대기) 스케쥴 이벤트는 그대로 표시한다.

\--no-libcall
:   라이브러리 호출을 추적하지 않는다.

\--no-merge
:   잎(leaf) 함수를 병합하지 않는다.

\--no-pltbind
:   동적 심볼 주소를 바인딩하지 않는다. (*LD_BIND_NOT*)

\--no-randomize-addr
:   ASLR(Address Space Layout Randomization)을 비활성화 한다.

\--nop
:   아무 작업도 하지 않는다. (성능 테스트 용)

\--num-thread=*NUM*
:   데이터를 저장하기 위해 *NUM* 개의 쓰레드를 사용한다.

-N, \--notrace=*FUNC*
:   FUNC들을 추적하지 않는다.

-p, \--pid=*PID*
:   대화형 mcount 인스턴스의 *PID* 에 연결한다.

\--port=*PORT*
:   네트워크 연결을 위해 *PORT* 를 사용한다. (기본값: 8090)

-P, \--patch=*FUNC*
:   FUNC에 동적 패칭을 적용한다.

\--record
:   주어진 스크립트를 실행하기 전에 새롭게 추적을 기록한다.

\--report
:   replay 전 실시간 보고서를 보여준다.

\--rt-prio=*PRIO*
:   실시간 (*FIFO*) 우선순위로 기록한다.

-r, \--time-range=*TIME*~*TIME*
:   *TIME* 시간 안에서만 기록된 추적 결과를 보여준다.
:   (타임스탬프 혹은 경과시간)

\--run-cmd=*CMDLINE*
:   데이터를 수신한 다음에 주어진 (쉘)명령어를 바로
:   실행한다.

-R, \--retval=*FUNC*[@retspec]
:   함수 *FUNC*에 대한 반환값을 주어진
:   uftrace retspec 에 맞게 보여준다.

\--sample-time=*TIME*
:   설정한 샘플링 타임에 해당하는 Flame graph 를 보여준다.

\--signal=*SIGNAL*@act[,act,...]
:   주어진 *SIGNAL* 을 받았을 때 주어진 액션을 실행한다.

\--sort-column=*INDEX*
:   *INDEX* 열을 기준으로 diff 보고서를 정렬한다. (기본값: 2)

\--srcline
:   가능한 각 함수들의 소스 줄번호를 표시한다.

\--symbols
:   기록된 정보 대신에 심볼(symbol) 테이블을 출력한다.

-s, \--sort=*KEY*[,*KEY*,...]
:   주어진 키를 기반으로 함수들을 정렬한다. (기본값: 2)

-S, \--script=*SCRIPT*
:   함수의 시작과 끝에 주어진 *SCRIPT* 를 수행한다.

-t, \--time-filter=*TIME*
:   설정한 시간 이하로 수행된 함수는 표시하지 않게 한다.

\--task
:   일반적인 함수 그래프 대신 태스크 그래프를 출력한다.

\--task-newline
:   태스크가 변경되면 빈 공백 한줄을 추가한다.

\--tid=*TID*[,*TID*,...]
:   주어진 태스크에 의해 호출된 함수들만 출력한다.

\--time
:   시간 정보를 출력한다.

-T, \--trigger=*FUNC*@act[,act,...]
:   FUNC 의 트리거를 설정한다.

-U, \--unpatch=*FUNC*
:   주어진 FUNC 함수에 대해 동적 패치를 적용하지 않는다.

\--with-syms=*DIR*
:   *DIR* 디렉터리 안에 있는 심볼 파일들을 사용한다.

-W, \--watch=*POINT*
:   *POINT* 가 변경되는 경우를 감시하고 기록한다.

-Z, \--size-filter=*SIZE*
:   *SIZE* 보다 큰 함수들에 동적 패칭을 적용한다.

더 구체적인 보조 명령별 옵션을 확인하기 위해선,
아래에 나열된 메뉴얼 페이지를 참조하라.


함께 보기
========
`uftrace-live`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-dump`(1), `uftrace-recv`(1), `uftrace-graph`(1), `uftrace-script`(1), `uftrace-tui`(1)


번역자
======
류준호 <ruujoon93@gmail.com>, 김성진 <mirusu400@naver.com>
