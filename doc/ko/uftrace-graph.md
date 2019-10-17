% UFTRACE-GRAPH(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace-graph - 기록된 데이터의 함수 호출 그래프를 출력한다.


사용법
======
uftrace graph [*options*] [*FUNCTION*]


설명
====
이 명령어는 대상 바이너리 또는 uftrace 형식으로 기록된 데이터에 있는 함수들에
대한 함수 호출 그래프를 출력한다.  만약 함수 이름을 생략하면 전체 함수 호출
그래프가 보여지고, 함수 이름이 하나 주어지면 대상 함수에 대한 백트레이스(backtrace)
들과 그 함수가 호출하는 함수들에 대한 호출 그래프를 보여준다.
결과에서 보이는 각 함수들의 정보에는 호출 횟수와 그 함수를 실행하는데 소요된 전체
시간이 함께 보여진다.


GRAPH 옵션
=========
-f *FIELD*, \--output-fields=*FIELD*
:   출력 필드를 사용자 지정으로 설정한다. 설정 가능한 값은 total, self, addr 이며
    쉼표를 사용하여 여러 필드를 설정할 수 있다.  'none' 과 같은 특수 필드를
    사용하여 모든 필드를 숨길 수 있으며 기본 설정은 'total' 이다.
    필드에 대한 상세한 내용은 *FIELDS* 를 참고할 수 있다.


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


예제
====
이 명령어는 아래와 같은 결과를 출력한다.

    $ uftrace record loop

    $ uftrace replay
    # DURATION    TID     FUNCTION
                [24447] | main() {
                [24447] |   foo() {
       8.134 us [24447] |     loop();
       7.296 us [24447] |     loop();
       7.234 us [24447] |     loop();
      24.324 us [24447] |   } /* foo */
                [24447] |   foo() {
       7.234 us [24447] |     loop();
       7.231 us [24447] |     loop();
       7.231 us [24447] |     loop();
      22.302 us [24447] |   } /* foo */
                [24447] |   bar() {
      10.100 ms [24447] |     usleep();
      10.138 ms [24447] |   } /* bar */
      10.293 ms [24447] | } /* main */

`graph` 명령어를 실행하면 다음과 같은 함수 호출 그래프를 출력한다.

    $ uftrace graph
    # Function Call Graph for 'loop' (session: 073f1e84aa8b09d3)
    ========== FUNCTION CALL GRAPH ==========
      10.293 ms : (1) loop
      10.293 ms : (1) main
      46.626 us :  +-(2) foo
      44.360 us :  | (6) loop
                :  | 
      10.138 ms :  +-(1) bar
      10.100 ms :    (1) usleep

가장 최상단에 있는 노드는 실제 함수가 아니라 실행 이미지의 이름을 나타낸다.
왼쪽에 있는 시간은 오른쪽에 있는 함수의 총 실행 시간을 나타낸다.
함수 이름 앞의 괄호 안의 숫자는 호출 횟수를 의미한다.  위에서 `main` 함수는
단 한번 호출되어 약 10 밀리초(msec) 동안 실행되었고, `foo` 함수는 두번 호출된
다음 그 안에서 `loop` 함수를 총 6 번 호출 하였다.

또한, `main` 함수는 `bar` 함수를 한번 호출하고, `bar` 함수는 다시 `usleep` 함수를
호출한 것을 알 수 있다.  이러한 분석 결과를 통해 `usleep` 함수는 `main` 함수에서
직접 호출 된것이 아님을 알 수 있다.

`graph` 명령어를 실행하고 `main` 함수명을 지정하면 아래와 같이 해당 함수의
호출 그래프와 함께 백트레이스 정보를 같이 보여준다.

    $ uftrace graph main
    # Function Call Graph for 'main' (session: 073f1e84aa8b09d3)
    =============== BACKTRACE ===============
     backtrace #0: hit 1, time  10.293 ms
       [0] main (0x4004f0)
    
    ========== FUNCTION CALL GRAPH ==========
    # TOTAL TIME   FUNCTION
       10.293 ms : (1) main
       46.626 us :  +-(2) foo
       44.360 us :  | (6) loop
                 :  | 
       10.138 ms :  +-(1) bar
       10.100 ms :    (1) usleep

'main' 함수는 최상위 함수이므로 백트레이스 결과가 없지만 `loop` 함수를 지정하면
다음과 같이 결과를 볼 수 있다.

    $ uftrace graph loop
    # Function Call Graph for 'loop' (session: 073f1e84aa8b09d3)
    =============== BACKTRACE ===============
     backtrace #0: hit 6, time  44.360 us
       [0] main (0x4004b0)
       [1] foo (0x400622)
       [2] loop (0x400f5f6)
    
    ========== FUNCTION CALL GRAPH ==========
    # TOTAL TIME   FUNCTION
       44.360 us : (6) loop

이 백트레이스 결과에서 `loop` 함수는 `foo` 함수에서 호출되었고 다시 `foo` 함수는
`main` 함수에서 호출된것을 알 수 있다.  `loop` 함수는 다른 함수를 호출하지 않는다.
이 경우에 `loop` 함수는 단 하나의 경로를 통해서만 호출되었기 때문에 backtrace #0
의 호출 횟수는 6 이된다.


FIELDS
======
uftrace 사용자는 graph 결과를 몇몇의 필드로 원하는 방식대로 구성할 수 있다.
여기서 필드란 콜론 문자 (:) 왼쪽에 나타나는 정보를 뜻한다.
기본적으로 전체실행시간 total 만을 필드로 사용하지만, 다른 필드들도 다음과 같이
임의의 순서로 사용 가능하다.

    $ uftrace record tests/t-abc
    $ uftrace graph -f total,self,addr
    # Function Call Graph for 't-sort' (session: b007f4b7cf792878)
    ========== FUNCTION CALL GRAPH ==========
    # TOTAL TIME  SELF TIME      ADDRESS     FUNCTION
       10.145 ms              561f652cd610 : (1) t-sort
       10.145 ms   39.890 us  561f652cd610 : (1) main
       16.773 us    0.734 us  561f652cd7ce :  +-(2) foo
       16.039 us   16.039 us  561f652cd7a0 :  | (6) loop
                                           :  |
       10.088 ms   14.740 us  561f652cd802 :  +-(1) bar
       10.073 ms   10.073 ms  561f652cd608 :    (1) usleep

각 필드는 다음과 같은 의미가 있다.

 * total: 함수의 전체 실행 시간
 * self : 자식 함수를 제외한 함수의 실행 시간
 * addr : 함수의 주소

기본적으로는 'total' 필드가 사용된다.  주어진 필드의 이름이 "+"로 시작하면
기본 필드에 추가하는것을 의미한다. 따라서 "-f +addr" 는 "-f total,addr" 와 같다.
또한 특별한 필드인 'none' 을 사용하면 아무런 필드도 출력하지 않게 할 수 있다.

    $ uftrace graph -f none
    # Function Call Graph for 't-sort' (session: b007f4b7cf792878)
    ========== FUNCTION CALL GRAPH ==========
    (1) t-sort
    (1) main
     +-(2) foo
     | (6) loop
     |
     +-(1) bar
       (1) usleep

이런 방식의 출력은 diff 도구를 사용하여 두 개의 서로 다른 그래프 출력을 비교할 때
유용하게 사용될 수 있다.


함께 보기
=========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-tui`(1)


번역자
======
김관영 <gy741.kim@gmail.com>
