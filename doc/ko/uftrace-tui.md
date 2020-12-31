% UFTRACE-TUI(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Jun, 2018

NAME
====
uftrace-tui - (Interactive) Text-based User Interface


사용법
======
uftrace tui [*options*]


설명
====
이 명령어는 graph, report 및 info 명령어와 같은 동일한 출력을 표시할 수 있는
터미널에서 대화창을 시작한다.  사용자는 키를 사용해서 결과를 쉽게 탐색할 수 있다.
추가적인 옵션들은 초기 데이터 로딩을 제한하는데 사용된다.


TUI 옵션
=========
-f *FIELD*, \--output-fields=*FIELD*
:   출력 필드를 사용자 지정으로 설정한다. 설정 가능한 값은 total, self, addr 이며
    쉼표를 사용하여 여러 필드를 설정할 수 있다.  'none' 과 같은 특수 필드를
    사용하여 모든 필드를 숨길 수 있으며 기본 설정은 'total' 이다.
    필드에 대한 설명은 `uftrace-graph`(1) 를 참고한다.


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

\--kernel-only
:   사용자 함수를 제외한 커널 함수만 출력한다.

\--event-full
:   사용자 함수 밖의 모든 (사용자) 이벤트를 출력한다.

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


OUTLINE
=======
일반적인 경우 전체적으로 하나의 세션만 있다면 그래프 모드로 시작해서 세션의
전체 함수 호출 그래프를 보여준다.  이후에 사용자 키들을 사용해서 다른 모드로
변경할 수 있으며 'h' 키를 사용해 도움말을 확인해 볼 수 있다.

현재 라인은 '>' 와 함께 반전된 색상으로 보여지며 화살표 키를 사용해 다른 위치로
이동할 수 있다.

     TOTAL TIME : FUNCTION
    >  7.548 us : (1) t-abc
       1.811 us :  ├─(1) __monstartup
                :  │
       1.266 us :  ├─(1) __cxa_atexit
                :  │
       4.471 us :  └─(1) main
       3.743 us :    (1) a
       3.194 us :    (1) b
       2.454 us :    (1) c
       1.000 us :    (1) getpid

     uftrace graph: session 2a22812ebbd06f40 (/tmp/uftrace/tests/t-abc)

세션이 두개 이상 있다면, 처음에 세션 선택 모드로 시작하게 된다.
그래프 모드의 정보는 각 세션을 분리해서 보여지지만 리포트 모드는 전체 세션의
결과를 통합해서 보여준다.

     Key uftrace command
    > G  call Graph for session #1: t-forkexec
         call Graph for session #2: t-abc
      R  Report functions
      I  uftrace Info
      h  Help message
      q  quit

     session a27acff69aec5c9c:  exe image: /tmp/uftrace/tests/t-forkexec


사용자 키
=========
TUI 창에서 다음과 같은 키들을 사용할 수 있음:

 * `Up`, `Down`:          커서를 위/아래로 움직임
 * `PageUp`, `PageDown`:  페이지를 위/아래로 움직임
 * `Home`, `End`:         첫번째/마지막 항목으로 이동
 * `Enter`:               그래프 접기/펴기 또는 세션 선택
 * `G`:                   현재 세션의 전체 그래프 창으로 전환
 * `g`:                   현재 함수의 백트레이스와 부분 호출 그래프 창으로 전환
 * `R`:                   uftrace report 창으로 전환
 * `r`:                   현재 함수를 기준으로 uftrace report 창으로 전환
 * `s`:                   다음 열의 항목으로 정렬 (report 모드에서)
 * `I`:                   uftrace info 창으로 전환
 * `S`:                   세션 목록 창으로 전환
 * `O`:                   현재 함수에 대한 편집기 열기
 * `c`/`e`:               직접 자식 그래프 노드 축소/확장
 * `C`/`E`:               모든 자식들의 그래프 노드 축소/확장
 * `n`/`p`:               같은 높이의 다음/이전 항목으로 이동 (그래프 모드에서)
 * `u`:                   부모 노드로 이동 (그래프 모드에서)
 * `l`:                   가장 긴 실행 시간을 갖는 자식 노드로 이동 (그래프 모드에서)
 * `j`/`k`:               커서를 위/아래로 움직임 (vi 기능과 같이)
 * `z`:                   현재 위치를 화면 중앙에 정렬
 * `/`:                   탐색 시작
 * `<`/`P`:               이전 일치 검색
 * `>`/`N`:               다음 일치 검색
 * `v`:                   디버그 정보 표시
 * `h`/`?`:               도움말 창 표시
 * `q`:                   종료


함께 보기
========
`uftrace`(1), `uftrace-graph`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-replay`(1)


번역자
======
전하은 <myjhe0608@gmail.com>, 민지수 <kuongee@gmail.com>
