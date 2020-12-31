% UFTRACE-RECORD(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace-record - 대상 프로그램의 함수 실행 흐름을 기록한다.


사용법
======
uftrace record [*options*] COMMAND [*command-options*]


설명
====
이 명령어는 COMMAND 로 대상 프로그램을 실행하고 함수들의 실행 흐름을 기록한다.
이 과정에서 아무것도 출력하지 않고 uftrace.data 디렉토리에 데이터를 저장한다.
이 데이터는 이후에 `uftrace replay` 나 `uftrace report` 등을 통해 분석될 수 있다.


RECORD 옵션
==============
-A *SPEC*, \--argument=*SPEC*
:   함수의 인자들을 기록한다.  이 옵션은 한번 이상 쓰일 수 있다.
    인자에 대한 설명은 *ARGUMENTS* 를 참고한다.

-R *SPEC*, \--retval=*SPEC*
:   함수들의 반환값을 기록한다.  이 옵션은 한번 이상 쓰일 수 있다.
    반환값에 대한 설명은 *ARGUMENTS* 를 참고한다.

-P *FUNC*, \--patch=*FUNC*
:   주어진 FUNC 함수를 동적으로 패치하여 추적하고 기록한다.
    이 옵션은 한번 이상 쓰일 수 있다.
    관련 설명은 *DYNAMIC TRACING* 을 참고한다.

-U *FUNC*, \--unpatch=*FUNC*
:   주어진 FUNC 함수에 대해 동적 패치를 적용하지 않는다.
    이 옵션은 한번 이상 쓰일 수 있다.
    관련 설명은 *DYNAMIC TRACING* 을 참고한다.

-Z *SIZE*, \--size-filter=*SIZE*
:   SIZE 바이트보다 큰 함수들을 동적으로 패치한다.
    동적추적에 대해서는 *DYNAMIC TRACING* 을 참고한다.

-E *EVENT*, \--event=*EVENT*
:   이벤트 추적을 활성화한다.  시스템 내에서 사용 가능한 이벤트여야 한다.

-S *SCRIPT_PATH*, \--script=*SCRIPT_PATH*
:   대상 프로그램이 실행하는 동안 함수의 진입과 반환 시점에 주어진 스크립트를
    활용해서 추가적인 작업을 한다.
    스크립트 언어 종류는 파일의 확장자를 통해 정해지는데 파이썬의 경우 ".py" 이다.
    스크립트 실행 설명은 *SCRIPT EXECUTION* 을 참고한다.

-W, \--watch=*POINT*
:   특정한 값이 변경되었을 경우 이를 보여주기 위해 watch point 를 추가한다.
    자세한 사항은 *WATCH POINT* 를 참고한다.

-a, \--auto-args
:   알려진 함수의 인자와 반환값들을 자동으로 기록한다.
    보통의 경우 C 언어 또는 시스템의 표준 라이브러리 함수들에 해당하지만,
    디버그 정보를 이용할 수 있다면 사용자 함수들에도 적용할 수 있다.

-l, \--nest-libcall
:   라이브러리들 간의 함수 호출도 함께 기록한다.
    기본적으로 uftrace 는 실행파일에서 직접 호출하는 라이브러리 함수만 기록한다.

-k, \--kernel
:   사용자 프로그램의 함수와 함께 커널 함수를 추적한다.
    기본적으로는 커널로의 진입 및 복귀 함수만 기록한다.
    이를 변경하려면 --kernel-depth 옵션을 사용할 수 있다.

-K *DEPTH*, \--kernel-depth=*DEPTH*
:   커널 최대 함수 깊이를 설정한다.
   --kernel 옵션이 자동으로 적용된다.

\--host=*HOST*
:   파일에 쓰지 않고, 주어진 호스트에게 추적 데이터를 네트워크 상으로 전송한다.
    데이터를 받기 위해서 `uftrace recv` 명령어가 목적지에서 실행되어야 한다.

\--port=*PORT*
:   `--host` 옵션을 이용해서 데이터를 네트워크로 보낼 때, 기본 포트(8090)가 아닌 다른 포트를 사용한다.

\--signal=*TRG*
:   함수가 아닌 선택한 시그널에 트리거를 설정한다.
    하지만 제한 사항들로 인하여 소수 트리거 기능만을 지원하고 있다.
    사용 가능한 작업: : trace_on, trace_off, finish.
    이 옵션은 두번 이상 사용할 수 있다.
    트리거 설명은 *TRIGGERS* 를 참고한다.

\--nop
:   어떤 함수도 record 하거나 replay하지 않는다. 이는 아무 일도 하지 않는 명령어로,
    성능 비교에서만 의미를 가진다.

\--force
:   약간의 문제가 있어도 uftrace 가 실행된다.
    `uftrace record` 는 실행파일에서 컴파일러에 의해 생성되는 mcount 를 찾을 수
    없을 때 uftrace 가 프로그램을 추적할 수 없으므로 오류 메시지와 함께 종료된다.
    단, 사용자는 동적으로 연결된 라이브러리 내의 기능에만 관심이 있을 수 있으며,
    이 경우 `--force` 옵션을 사용하여 uftrace 를 실행시킬 수 있다.
    또한 `-A`/`--argument` 및 `-R`/`--retval` 옵션은 -pg 로 컴파일된 바이너리에
    대해서만 작동하므로, uftrace 는 그 옵션 없이 빌드된 바이너리를 실행하려고
    할 때에도 종료된다.
    이 옵션은 경고를 무시하고 인수 및 반환 값 없이 uftrace 를 실행시키도록 한다.

\--time
:   time(1) 스타일로 실행시간을 출력한다.


공통 옵션
==============
-F *FUNC*, \--filter=*FUNC*
:   선택된 함수들 (그리고 그 내부의 함수들)만 출력하도록 필터를 설정한다.
    이 옵션은 한번 이상 쓰일 수 있다. 필터에 대한 설명은  *FILTERS* 를
    참고한다.

-N *FUNC*, \--notrace=*FUNC*
:   선택된 함수들 (또는 그 아래 함수들)을 출력에서 제외하도록 설정하는 옵션이다.
    이 옵션은 한번 이상 쓰일 수 있다. 필터에 대한 설명은 *FILTERS* 를
    참고한다.

-C *FUNC*, \--caller-filter=*FUNC*
:   선택된 함수의 호출자를 출력하는 필터를 설정한다. 이 옵션은 한번 이상 쓰일 수 있
    다. 필터에 대한 설명은 *FILTERS* 를 참고한다.

-T *TRG*, \--trigger=*TRG*
:   선택된 함수의 트리거를 설정한다. 이 옵션은 한번 이상 쓰일 수 있다. 트리거에
    대한 설명은 *TRIGGERS* 를 참고한다.

-D *DEPTH*, \--depth=*DEPTH*
:   함수가 중첩될 수 있는 최대 깊이를 설정한다. (이를 넘어서는 상세한 함수 실행과정
    은 무시한다.) 필터에 대한 설명은 *FILTERS* 를 참고한다.

-t *TIME*, \--time-filter=*TIME*
:   설정한 시간 이하로 수행된 함수는 표시하지 않게 한다. 만약 어떤 함수가 명시적
    으로 '추적' trigger가 적용된 경우, 그 함수는 실행 시간과 상관없이 항상
    출력된다. 필터에 대한 설명은 *FILTERS* 를 참고한다.

\--no-libcall
:   라이브러리 호출은 표시하지 않게 한다.

\--no-event
:   이벤트는 표시하지 않게 한다.

\--match=*TYPE*
:   TYPE으로 일치하는 패턴을 보여준다. 가능한 형태는 `regex`와 `glob`이다.
    기본은 `regex`이다.

\--disable
:   추적을 사용하지 않은 채로 uftrace를 시작한다. 이것은 `trace_on` 트리거와 함께 
    사용되었을 때만 의미를 가진다.


RECORD 설정 옵션
=====================
-L *PATH*, \--library-path=*PATH*
:   필요한 내부 라이브러리를 *PATH* 에서 먼저 찾는다.
    이 옵션은 대부분 테스트 목적으로 사용된다.

-b *SIZE*, \--buffer=*SIZE*
:   저장할 데이터의 내부 버퍼 크기를 설정한다.  기본 사이즈는 128k 이다.

\--kernel-buffer=*SIZE*
:   저장할 커널 데이터의 내부 버퍼 크기를 설정한다.
    커널 내부의 기본 설정은 1408k 이다.

\--no-pltbind
:   동적 심볼 주소를 바인딩하지 않는다.  이 옵션은 `LD_BIND_NOT` 환경 변수를
    사용하여 동시적으로 발생하는 (첫 번째) 접근으로 인해 누락될 수 있는
    라이브러리 함수를 추적한다.  `--no-libcall` 옵션과 함께 이 옵션을 사용하는
    것은 의미가 없다.

\--max-stack=*DEPTH*
:   내부적으로 기록하는 함수 호출 스택의 최대 깊이를 설정한다.  기본값은 1024 이다.

\--num-thread=*NUM*
:   데이터를 저장하기 위해 *NUM* 개의 쓰레드를 사용한다.  기본적으로는 사용 가능한
    CPU 의 1/4 으로 설정한다.  (하지만 커널을 포함해 전체를 기록하는 경우, 최대로
    사용 가능한 CPU 의 수로 설정한다.)

\--libmcount-single
:   빠른 데이터 기록을 위해서 libmcount 의 단일 쓰레드 버전을 사용한다.
    대상 프로그램이 pthread 라이브러리를 사용하는 경우에는 무시된다.

\--rt-prio=*PRIO*
:   데이터 기록을 하는 스레드를 *PRIO* 를 우선순위로 갖는 실시간(FIFO)로
    향상시킨다.  이 옵션은 특히 대규모 데이터를 기록하는 전체 커널 추적과 같은
    환경에서 유용하다.

\--keep-pid
:   프로그램을 추적할 때 동일한 pid 값을 유지하게 해준다.
    일부 데몬 프로세스의 경우 분기 할 떄 동일한 pid 를 갖는것이 중요하다.
    일반적으로 uftrace 를 실행하면 fork() 를 내부적으로 다시 호출하므로
    pid 가 변경된다.  이 옵션을 사용할 경우 터미널 설정이 손상되는 경우가 있기
    떄문에 `--no-pager` 옵션과 함께 사용하는 것이 좋다.

\--no-randomize-addr
:   ASLR(Address Space Layout Randomization)을 비활성화 한다.
    이는 프로세스의 라이브러리 로딩 주소가 매번 변경되지 않도록 막아준다.

\--srcline
:   디버그 정보에 레코드한 소스 줄번호를 표시한다.


FILTERS
=======
uftrace 는 관심 있는 대상이 아닌 함수들을 감추는 필터링을 할 수 있다.
필터링은 사용자들이 관심 있는 함수들에만 집중할 수 있게 하고, 기록되는 데이터의
크기를 줄일 수 때문에 사용하기를 권장한다.
uftrace 가 호출되면, 두 종류의 함수 필터를 갖게 되는데 이들은 대상 함수를
선택하는 방식(opt-in)의 필터로 `-F`/`--filter` 와 선택하지 않는 방식(opt-out)의
필터인 `-N`/`--notrace` 가 있다.
이 필터들은 기록(record)하거나 재생(replay)할 때 모두 적용될 수 있다.

첫번째 필터 종류는 선택하는 방식의 필터이다. 기본적으로, 이것은 아무것도 추적하지
않는다.  하지만 어떤 명시된 함수에 진입하면, 함수 호출에 대한 추적을 시작한다.
그러다가 그 함수가 반환하게 되면, 함수 호출 추적을 중단한다.

예를 들어, `a()`, `b()` 와 `c()`를 차례로 호출하는 간단한 프로그램을 생각해보자.

    $ cat abc.c
    void c(void) {
        /* do nothing */
    }

    void b(void) {
        c();
    }

    void a(void) {
        b();
    }

    int main(void) {
        a();
        return 0;
    }

    $ gcc -pg -o abc abc.c

일반적인 경우 uftrace 는 `main()`부터 `c()`까지의 모든 함수들을 추적할 것이다.

    $ uftrace record ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
                [ 1234] |     b() {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

하지만 `-F b` 필터 옵션이 사용되었을 때는, `main()`과 `a()` 함수는 보이지 않고
오직 `b()`와 `c()`만이 포함된 추적 결과를 보일것이다.

    $ uftrace record -F b ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

두번째 필터 종류는 선택하지 않는 방식의 필터이다.  기본적으로, 모든 것이
추적되지만, 명시된 함수에 진입하게 되면, 추적을 멈춘다.  제외된 함수가 반환하게
되면, 추적을 재개한다.

위 예시에서, `b()` 함수와 그의 모든 호출은 `-N` 옵션으로 생략할 수 있다.

    $ uftrace record -N b ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

만일 특정 함수에만 관심이 있고 그 함수가 어떻게 호출되는지만 알고 싶다면,
caller filter 를 사용하면 될 것이다. 그 함수를 마지막(leaf) 노드로 만들고,
그 함수의 모든 부모 함수들을 기록한다.

    $ uftrace record -C b ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

위 예시에서, 호출 경로에 없는 함수들을 출력되지 않았다. 또한, 함수 `b()`의 자식 함수인
함수 `c()` 또한 출력되지 않았다.

또한, `-D` 옵션으로 함수의 중첩 깊이을 제한할 수도 있다.

    $ uftrace record -D 3 ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

위 예시에서, uftrace 는 함수 호출 깊이를 최대 3 으로 제한하여 출력했기 때문에,
마지막 함수인 `c()`는 생략되었다. `-D` 옵션은 `-F` 옵션과 함께 쓰일 수 있다.

때로는, 오랜 시간 실행되는 함수들을 특별하게 관찰하는 것이 유용하다.
이는 작은 (실행시간을 가지는) 함수들 중에는 관심 대상이 아닌 것들이 많기 때문이다.
`-t`/`--time-filter` 옵션은 명시된 임계시간보다 오래 실행된 함수들만 볼 수 있게
하는 시간 기반의 필터이다.  위 예시에서는, 사용자는 대부분 아래와 같이
5 마이크로(us) 초 이상 걸려서 실행되는 함수를 보고 싶어할 것이다.

    $ uftrace record -t 5us ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

필터링된 함수에 트리거를 설정할 수도 있다.  더 많은 정보는 *TRIGGERS* 항목에서
참고할 수 있다.

커널 함수 추적을 설정하면, `@kernel` 식별자를 통해 커널 함수에 대한 필터를 적용할
수 있다.  이하 예시에서는 모든 사용자 함수와 (커널 레벨의) page fault 핸들러들을
보여준다.

    $ sudo uftrace -k -F '.*page_fault@kernel' ./abc
    # DURATION    TID     FUNCTION
               [14721] | main() {
      7.713 us [14721] |   __do_page_fault();
      6.600 us [14721] |   __do_page_fault();
      6.544 us [14721] |   __do_page_fault();
               [14721] |   a() {
               [14721] |     b() {
               [14721] |       c() {
      0.860 us [14721] |         getpid();
      2.346 us [14721] |       } /* c */
      2.956 us [14721] |     } /* b */
      3.340 us [14721] |   } /* a */
     79.086 us [14721] | } /* main */


TRIGGERS
========
uftrace 는 (필터가 있든 없든) 선택된 함수 호출과 시그널에 대한 트리거 동작을
지원한다.  현재 지원되는 트리거와 사양에 대한 BNF 는 다음과 같다.

    <trigger>    :=  <symbol> "@" <actions>
    <actions>    :=  <action>  | <action> "," <actions>
    <action>     :=  "depth="<num> | "backtrace" | "trace" | "trace_on" | "trace_off" |
                     "recover" | "color="<color> | "time="<time_spec> | "read="<read_spec> |
                     "finish" | "filter" | "notrace"
    <time_spec>  :=  <num> [ <time_unit> ]
    <time_unit>  :=  "ns" | "nsec" | "us" | "usec" | "ms" | "msec" | "s" | "sec" | "m" | "min"
    <read_spec>  :=  "proc/statm" | "page-fault" | "pmu-cycle" | "pmu-cache" | "pmu-branch"

`depth` 트리거는 함수를 실행하는 동안 필터의 깊이를 변경한다.  다양한 함수에 대해
서로 다른 필터 깊이를 설정할 수 있다.  그리고 `backtrace` 트리거는 replay 시 스택
백트레이스를 출력한다.

`color` 트리거는 replay 명령어에서 색상을 변경한다.  지원되는 색상은 `red`,
`green`, `blue`, `yellow`, `magenta`, `cyan`, `bold`, `gray` 가 있다.

다음 예제는 트리거 작동 방식을 보여준다.  전역 필터 깊이가 5 로 설정되어 있지만
`b()` 함수에 `depth` 트리거를 설정하여 `b()` 아래 함수는 보이지 않게된다.

    $ uftrace record -D 5 -T 'b@depth=1' ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

`backtrace` 트리거는 replay 에서만 사용할 수 있다.

`trace_on`과 `trace_off` 트리거는 uftrace 가 지정된 함수를 기록할지 여부를
관리한다.  또한, `_` 문자 없이 `traceon` 과 `traceoff` 로도 사용할 수 있다.

`recover` 트리거는 프로세스가 호출 스택(call stack)에 직접 접근하는 일부 경우에
사용된다.  예를들어, v8 자바스크립트 엔진을 추적하는 동안 가비지 컬렉션 단계에서
세그멘테이션 폴트 문제가 발생된다면 이는 v8 이 (변경된) 반환 주소를 통해 컴파일된
코드 객체에 접근하려 하기 때문이다.
`recover` 트리거는 함수 진입점에 원래 반환 주소를 복원하고 함수 반환점에서
다시 uftrace 에서 조작한 반환 주소로 재설정한다.  (특히 v8 자바스크립트 엔진
사례에서 `ExitFrame::Iterate` 함수와 같이 문제를 발생시키는 상황에서 `recover`
트리거를 사용하면 문제를 해결할 수 있다.)


`time` 트리거는 함수를 실행하는 동안 시간 필터(time-filter) 설정을 변경한다.
다른 함수들에 대해서 서로 다른 시간 필터를 적용할 떄 사용할 수 있다.

`read` 트리거는 실행 시에 일부 정보를 읽을 수 있다.  결과는 주어진 함수의 시작과
끝에 (내장) 이벤트의 형태로 기록된다.  현재 다음과 같은 이벤트가 지원되고 있다.

 * "proc/statm": /proc 으로부터의 메모리 사용량 정보
 * "page-fault": getrusage(2)를 사용한 페이지 폴트(page fault) 횟수
 * "pmu-cycle":  perf-event 시스템콜을 통한 cpu 클럭 사이클 및 명령어 실행 횟수
 * "pmu-cache":  perf-event 시스템콜을 통한 캐시 참조(reference) 및 실패(miss)
 * "pmu-branch": Perf-event 시스템콜을 사용한 분기예측(branch prediction) 및 실패(miss)

결과는 아래와 같이 주석의 형태로 이벤트 정보가 출력된다.

    $ uftrace record -T a@read=proc/statm ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
                [ 1234] | main() {
                [ 1234] |   a() {
                [ 1234] |     /* read:proc/statm (size=6808KB, rss=776KB, shared=712KB) */
                [ 1234] |     b() {
                [ 1234] |       c() {
       1.448 us [ 1234] |         getpid();
      10.270 us [ 1234] |       } /* c */
      11.250 us [ 1234] |     } /* b */
                [ 1234] |     /* diff:proc/statm (size=+4KB, rss=+0KB, shared=+0KB) */
      18.380 us [ 1234] |   } /* a */
      19.537 us [ 1234] | } /* main */


`finish` 트리거는 기록(record)을 종료할 떄 사용한다.  데몬과 같이 종료되지 않는
프로세스를 추적하는 데 유용할 수 있다.

`filter` 와 `notrace` 트리거는 각각 `-F`/`--filter` 와 `-N` /`--notrace` 같은
효과가 있다.

트리거는 현재 커널 함수를 제외한 사용자 함수들에서만 동작한다.

트리거는 시그널로도 사용할 수 있다.  이는 `signal` 트리거에 의해 수행되며
함수 트리거와 비슷하지만 현재는 "trace_on", "trace_off" 및 "finish" 트리거만
지원되고 있다.

    $ uftrace record --signal 'SIGUSR1@finish' ./some-daemon


ARGUMENTS
=========
uftrace 는 함수의 인자와 반환값을 각각 `-A`/`\--argument` 와 `-R`/`\--retval` 로
기록할 수 있다.
이에 대한 문법체계는 트리거와 매우 유사하다.

    <argument>    :=  <symbol> [ "@" <specs> ]
    <specs>       :=  <spec> | <spec> "," <spec>
    <spec>        :=  ( <int_spec> | <float_spec> | <ret_spec> )
    <int_spec>    :=  "arg" N [ "/" <format> [ <size> ] ] [ "%" ( <reg> | <stack> ) ]
    <float_spec>  :=  "fparg" N [ "/" ( <size> | "80" ) ] [ "%" ( <reg> | <stack> ) ]
    <ret_spec>    :=  "retval" [ "/" <format> [ <size> ] ]
    <format>      :=  "d" | "i" | "u" | "x" | "s" | "c" | "f" | "S" | "p"
    <size>        :=  "8" | "16" | "32" | "64"
    <reg>         :=  <arch-specific register name>  # "rdi", "xmm0", "r0", ...
    <stack>       :=  "stack" [ "+" ] <offset>

`-A`/`\--argument` 옵션은 symbol 의 이름과 그것의 spec 들을 선택적으로 받는다.
spec 은 argN 으로 시작되는데 여기서 N 은 인자의 인덱스값이다.  인덱스는 1 부터
시작되며, 순서는 함수호출규약(calling convention)의 인자 전달 순서와 대응된다.
인자의 인덱스는 정수형 (혹은 포인터형) 과 부동소수점형 각각 따로 관리된다는 점,
그리고 이들은 함수호출규약에 따라 각기 간섭을 일으킬 수 있다는 점에 유의하라.
argN 은 정수형 인자를, fpargN 은 부동소수점형 인자를 위한 표기이다.

"d" 형식 혹은 아무 형식도 주지 않을 경우, uftrace 는 정수형은 'long int'형으로
간주하고 소수점형에 대해서는 'double'형으로 간주한다.

"i" 형식은 signed 정수형으로, "u" 형식은 unsigned 으로 출력한다.
두 형식 모두 10 진수가 출력되는 한편 "x" 형식은 16 진수로 출력되게 한다.
"s" 는 null 을 제외한 문자열 출력을 위한 형식이고, "c" 는 단일 문자를 위한
형식이다.  "f" 형식은 부동 소수점을 출력하는데, (일반적으로) 반환값에서만 의미를
가진다.
fpargN 은 항상 소수점 방식이기 때문에 어떤 형식 필드도 없음에 유의하라.
"S" 형식은 std::string 을 위한 형식이지만, 아직까지는 libstdc++ 라이브러리만
지원가능하다.  마지막으로, "p" 형식은 함수포인터 형식이다. 추적 대상의 주소가
기록되면, 언제나 함수 이름으로 출력된다.

문자열 타입의 인자를 사용할 때 (포인터) 값이 유효하지 않을 경우 프로그램을
비정상 종료시킬 수 있음에 주의하라.  사실 uftrace 는 유효한 프로세스 주소 공간의
범위를 지속적으로 점검하려고 노력하지만, 몇몇의 경우들을 놓칠 수 있다.

또한 특정 레지스터의 이름이나 스택 오프셋(offset)으로도 인자로 명시할 수 있다.
(반환값은 불가하다)
아래는 인자로 사용될 수 있는 레지스터 이름들이다.

 * x86: rdi, rsi, rdx, rcx, r8, r9 (for integer), xmm[0-7] (for floating-point)
 * arm: r[0-3] (for integer), s[0-15] or d[0-7] (for floating-point)

예시는 아래와 같다.

    $ uftrace record -A main@arg1/x -R main@retval/i32 ./abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main(0x1) {
                [ 1234] |   a() {
                [ 1234] |     b() {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } = 0; /* main */

    $ uftrace record -A puts@arg1/s -R puts@retval ./hello
    Hello world

    $ uftrace replay
    # DURATION    TID     FUNCTION
       1.457 us [21534] | __monstartup();
       0.997 us [21534] | __cxa_atexit();
                [21534] | main() {
       7.226 us [21534] |   puts("Hello world") = 12;
       8.708 us [21534] | } /* main */

이 인자들과 반환값들은 실행파일이 `-pg` 옵션으로 빌드되었을 때에만 기록됨에 유의하라.
`-finstrument-functions` 로 만들어진 실행파일들은 라이브러리 호출을 제외하고는 무시된다.
인자와 반환값의 기록은 아직까진 사용자 정의 함수에서만 동작한다.

만일 프로그램이 DWARF 와 같은 디버그 정보와 함께 빌드되었다면,
(libdw 와 함께 빌드된) uftrace 는 자동으로 인자들의 갯수와 자료형들을 식별할 수
있다.  또한 디버그 정보를 사용하지 않더라도, 몇몇 잘 알려진 라이브러리 함수들의
인자들과 반환값은 기본적으로 제공된다.
이 경우 사용자는 인자들의 spec 과 반환값을 수동적으로 명시할 필요가 없이 함수의
이름 (또는 패턴) 만 주는 것으로도 충분하다.  사실, 명시적으로 argspec 을 지정하면
자동 argspec 을 표시되지 않게 한다.

예를 들어, 위의 예시는 아래와 같이 작성할 수 있다.

    $ uftrace record -A . -R main ./hello
    Hello world

    $ uftrace replay -F main
    # DURATION     TID     FUNCTION
                [ 18948] | main(1, 0x7ffeeb7590b8) {
       7.183 us [ 18948] |   puts("Hello world");
       9.832 us [ 18948] | } = 0; /* main */

인자 패턴 (".")은 모든 문자에 대응되기 때문에 모든 (지원되는) 함수들이
기록되었음에 유의하라.  위에서는 "main" 함수의 두 인자들과 "puts" 의 한 문자열
인자를 보여준다.  만일 (지원되는) 함수의 모든 인자들과 반환값들을 보고 싶다면,
`-a`/`\--auto-args` 옵션을 사용하라.


DYNAMIC TRACING
===============
uftrace 는 x86_64, AArch64 환경의 런타임 (정확하게는, 로드 타임) 에서
동적추적(dynamic tracing)이 가능하다.  함수를 기록하기 전에, 보통 프로그램을
`-pg` (혹은 `-finstrument-functions`으로) 빌드해야 하고, 그렇게 된다면 모든
함수들이 `mcount()`를 호출하기 때문에 어느 정도 성능에 영향을 받게 될 것이다.

동적추적을 할 때, `-P`/`--patch` 옵션을 통해 특정 함수만을 추적할 수 있다.
capstone 디스어셈블리 엔진을 사용한다면 위 옵션을 지정해서 프로그램을
(재)컴파일할 필요가 없다.  이제 uftrace 는 명령어들을 분석할 수 있게 되고
(만약 가능하다면) 그 명령어들을 다른 곳에 복사하여 `mcount()` 함수들을 호출하여
uftrace 로 추적할 수 있게 바이너리를 조작 할 수 있다.
그 이후 제어권은 복사된 명령어로 넘어가게 되고, 그 다음에야 남은 명령어들로
반환하게 된다.

capstone 을 사용할 수 없다면, 프로그램을 빌드할 때 몇몇 컴파일러 (gcc) 옵션들을
추가해야 할 것이다.  gcc 5.1 버전 이상부터는 `-mfentry`와 `-mnop-mcount` 옵션을
제공하는데 이 옵션들은 함수 맨 앞에 `mcount()` 와 같은 함수 추적을 위한 코드를
추가하고 그 명령어를 NOP 으로 변환한다.  그렇게 되면 일반적인 조건에서 실행할
때에는 성능 상의 오버헤드가 거의 없어질 것이다.  uftrace 는 `-P` 옵션을 이용하여
선택적으로 `mcount()` 함수를 호출할 수 있도록 전환할 수 있다.

uftrace 를 아래의 예제에서 평소처럼 사용할때에는 에러 메세지를 보여준다.
그 이유는 바이너리가 어떤 `mcount()` 와 같은 함수 추적을 위한 코드도 호출하지
않기 때문이다.

    $ gcc -o abc -pg -mfentry -mnop-mcount tests/s-abc.c
    $ uftrace abc
    uftrace: /home/namhyung/project/uftrace/cmd-record.c:1305:check_binary
      ERROR: Can't find 'mcount' symbol in the 'abc'.
             It seems not to be compiled with -pg or -finstrument-functions flag
             which generates traceable code.  Please check your binary file.

하지만 `-P a` 패치 옵션을 적용한다면, 동적으로 `a()` 함수만을 추적할 것이다.

    $ uftrace record --no-libcall -P a abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
       0.923 us [19379] | a();

추가로, '.'을 이용해 (glob은, '*') `P`옵션과 함께 정규표현식으로 쓰인 문자에 대해
하나라도 매칭되는 모든 함수들에 대해서도 적용시킬 수 있다.

    $ uftrace record --no-libcall -P . abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
                [19387] | main() {
                [19387] |   a() {
                [19387] |     b() {
       0.940 us [19387] |       c();
       2.030 us [19387] |     } /* b */
       2.451 us [19387] |   } /* a */
       3.289 us [19387] | } /* main */

`-U` 옵션은 `-P` 옵션과 반대로 작용한다. 이 옵션들이 같이 쓰이면 나중에 쓰여진
옵션이 그 이전의 옵션을 대체하는 효과를 갖는다.
예를 들면 만약 당신이 'a' 를 제외한 모든 함수를 추적하고 싶은 경우는 아래와 같이
사용할 수 있다.

    $ uftrace record --no-libcall -P . -U a  abc
    $ uftrace replay
    # DURATION    TID     FUNCTION
                [19390] | main() {
                [19390] |   b() {
       0.983 us [19390] |     c();
       2.012 us [19390] |   } /* b */
       3.373 us [19390] | } /* main */

여기서 순서가 중요한데 만약 순서를 `-U a -P .` 와 같이 사용하면 모든 함수들을
기록하는 결과를 보이는데 이는 `-P .` 가 다른 모든것에 우선해 작용해서이다.

추가적으로, `-U` 옵션은 `-pg`(그리고 `-mfentry 또는 `-mrecord-mcount`)로 컴파일된
바이너리에 대해서도 사용 가능하다.  이 기능에 대해서는 capstone 이 명령어를
분석할 수 있어야 한다.

Clang/LLVM 4.0은 [X-ray](http://llvm.org/docs/XRay.html)라는 기술을 제공한다.
이는 `gcc -mfentry -mnop-mcount` 와 `-finstrument-functions` 를 결합한 것과도
유사하다.  uftrace는 `X-ray`로 빌드된 실행파일에 대해서도 동적추적을 지원한다.

예를 들어, 대상 프로그램을 clang 으로 아래의 옵션으로 빌드할 수도 있지만,
그와 동일하게 동적추적을 위해 아래와 같이 `-P` 옵션을 사용할 수도 있을 것이다.

    $ clang -fxray-instrument -fxray-instruction-threshold=1 -o abc-xray  tests/s-abc.c
    $ uftrace record -P main abc-xray
    $ uftrace replay
    # DURATION    TID     FUNCTION
                [11093] | main() {
       1.659 us [11093] |   getpid();
       5.963 us [11093] | } /* main */

    $ uftrace record -P . abc-xray
    $ uftrace replay
    # DURATION    TID     FUNCTION
                [11098] | main() {
                [11098] |   a() {
                [11098] |     b() {
                [11098] |       c() {
       0.753 us [11098] |         getpid();
       1.430 us [11098] |       } /* c */
       1.915 us [11098] |     } /* b */
       2.405 us [11098] |   } /* a */
       3.005 us [11098] | } /* main */


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

위 스크립트는 아래와 같이 기록된 시간 순으로 실행될 수 있다:

    $ uftrace -S scripts/simple.py -F main tests/t-abc
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
    # DURATION    TID     FUNCTION
                [10929] | main() {
                [10929] |   a() {
                [10929] |     b() {
                [10929] |       c() {
       4.293 us [10929] |         getpid();
      19.017 us [10929] |       } /* c */
      27.710 us [10929] |     } /* b */
      37.007 us [10929] |   } /* a */
      55.260 us [10929] | } /* main */

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

'script_context' 에 있는 각 항목들은 스크립트 내에서 읽을 수 있다.
스크립팅에 대한 자세한 사항은 `uftrace-script`(1)를 참고할 수 있다.


WATCH POINT
===========
uftrace 의 watch point 는 특정 값의 변경사항을 출력한다.  개념적으로는 일반적인
디버거의 watch point 와 같지만, 함수의 진입과 종료에만 적용되기 때문에 몇몇
변경사항들은 놓칠 수도 있다.

아직까지는, 아래의 watch point 들만이 지원된다.

 * "cpu" : 현재 작업을 수행하는 cpu 번호

트리거를 읽을 때처럼, 결과는 다음과 같이 주석 형식의 이벤트로 출력된다.

    $ uftrace -W cpu tests/t-abc
    # DURATION     TID     FUNCTION
                [ 19060] | main() {
                [ 19060] |   /* watch:cpu (cpu=8) */
                [ 19060] |   a() {
                [ 19060] |     b() {
                [ 19060] |       c() {
       2.365 us [ 19060] |         getpid();
       8.002 us [ 19060] |       } /* c */
       8.690 us [ 19060] |     } /* b */
       9.350 us [ 19060] |   } /* a */
      12.479 us [ 19060] | } /* main */


함께 보기
=========
`uftrace`(1), `uftrace-replay`(1), `uftrace-report`(1), `uftrace-recv`(1), `uftrace-graph`(1), `uftrace-script`(1), `uftrace-tui`(1)


번역자
======
강민철 <tegongkang@gmail.com>, 김홍규 <honggyu.kp@gmail.com>
