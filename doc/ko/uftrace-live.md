% UFTRACE-LIVE(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace-live - 실행 도중 함수들을 기록한다.


사용법
========
uftrace [live] [*옵션*] COMMAND [*명령어-옵션*]


설명
===========
이 명령어는 COMMAND를 실행하고 함수의 시간과 쓰레드 정보를 출력한다.
이는 기본적으로 `uftrace record`와 `uftrace replay`를 차례로 실행하는 것과 같지만,
데이터 파일을 저장해주지는 않는다.
이 명령어는 `record`나 `replay` 명령어가 받는 대부분의 인자들을 받는다.


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


LIVE 옵션
============
\--list-event
:   실행 중 사용가능한 이벤트들을 보여준다.

\--report
:   replay전 live-report를 보여준다.


RECORD 옵션
==============
-A *SPEC*, \--argument=*SPEC*
:   함수의 인자들을 record한다. 이 옵션은 한번 이상 쓰일 수 있다.
    인자에 대한 설명은 *ARGUMENTS*를 참고한다.

-R *SPEC*, \--retval=*SPEC*
:   함수들의 리턴값을 record한다. 이 옵션은 한번 이상 쓰일 수 있다.
    인자에 대한 설명은 *ARGUMENTS*를 참고한다.

-P *FUNC*, \--patch=*FUNC*
:   주어진 FUNC 함수를 동적으로 패치하여 추적한다.
    이 옵션은 한번 이상 쓰일 수 있다. 동적 추적은 *DYNAMIC TRACING*를 참고한다.

-E *EVENT*, \--event=*EVENT*
:   이벤트 추적을 활성화한다. 시스템 내에서 사용 가능한 이벤트여야 한다.

-S *SCRIPT_PATH*, \--script=*SCRIPT_PATH*
:   기록된 추적 데이터를 수행하는 동안 주어진 스크립트가 함수의 시작과 끝에서 추가적인 작업을 하도록 한다. 
    스크립트 언어는 파일의 확장자를 통해 정해진다 (파이썬은 ".py" 파일을 사용한다).
    스크립트 실행 설명은 *스크립트 실행*을 참고한다.

-W, \--watch=*POINT*
:   값이 변경되었을 경우 조사식을 추가하여 포인트를 표시한다. 조사식 설명은 *조사식*을 참고한다.

-a, \--auto-args
:   알려진 함수의 인수 및 반환 값을 자동으로 기록한다.
    보통 표준 라이브러리 함수들에 해당하지만,
    디버그 정보를 이용할 수 있다면 사용자 함수들에도 적용할 수 있다.

-l, \--nest-libcall
:   라이브러리 간 함수 호출을 추적한다.
    기본적으로, uftrace는 실행파일의 라이브러리 호출만 기록한다.

-k, \--kernel
:   사용자 프로그램의 함수와 함께 커널 함수를 추적한다. 
    기본적으로는 커널로의 진입 및 복귀 함수만 기록한다. 
    이를 변경하려면 --kernel-depth 옵션을 사용할 수 있다.

-K *DEPTH*, \--kernel-depth=*DEPTH*
:   커널 최대 함수 깊이를 설정한다.
   --kernel 옵션이 자동으로 적용된다.

\--signal=*TRG*
:   함수가 아닌 선택한 시그널에 트리거를 설정한다.
    하지만 제한 사항들로 인하여 소수 트리거 기능만을 지원하고 있다.
    사용 가능한 작업: : trace_on, trace_off, finish. 
    이 옵션은 두번 이상 사용할 수 있다. 
    트리거 설명은 *트리거*를 참고한다.

\--nop
:   어떤 함수도 record 하거나 replay하지 않는다. 이는 아무 일도 하지 않는 명령어로, 
    성능 비교에서만 의미를 가진다.

\--force
:   약간의 문제가 있어도 uftrace가 실행된다.
    `uftrace record`는 실행파일에서 mcount 기호(compiler에 의해 생성됨)를 찾을 수 
    없을 때 uftrace가 프로그램을 추적할 수 없으므로 오류 메시지와 함께 종료된다.
    단, 사용자는 동적으로 연결된 라이브러리 내의 기능에만 관심이 있을 수 있으며, 
    이 경우 `--force` 옵션을 사용하여 uftrace를 실행시킬 수 있다. 
    또한 `-A`/`--argument` 및 `-R`/`--retval` 옵션은 -pg가 내장된 바이너리에 
    대해서만 작동하므로, uftrace는 그 옵션 없이 빌드된 바이너리를 실행하려고 할 때 종료된다. 
    이 옵션은 경고를 무시하고 인수 및 반환 값 없이 uftrace를 실행시켜준다.

\--time
:   time(1) 스타일로 실행시간을 출력한다.


RECORD CONFIG 옵션
=====================
-L *PATH*, \--library-path=*PATH*
:   필요한 내부 라이브러리를 *PATH*에 로드한다. 이 옵션은 대부분 테스트 목적으로 사용된다.

-b *SIZE*, \--buffer=*SIZE*
:   데이터를 추적한 내부 버퍼 크기가 저장된다. 기본 사이즈는 128k이다.

\--kernel-buffer=*SIZE*
:   커널을 추적하는 버퍼 크기를 설정한다. (커널 내부) 기본 값은 1408k이다.

\--no-pltbind
:   동적 기호 주소를 묶는 것을 막는다.
    이 옵션은 `LD_BIND_NOT` 환경 변수를 사용하여 동시(첫 번째) 액세스로 인해 빠질 수 있는 라이브러리 함수를 추적한다.
    `--no-libcall` 옵션과 함께 이 옵션을 사용하는 것은 의미가 없다.

\--max-stack=*DEPTH*
:   호출에 쓰이는 함수 호출 스택의 최대 깊이를 설정한다. 기본값은 1024이다. 

\--num-thread=*NUM*
:   추적한 데이터를 저장하기 위해 *NUM* 쓰레드를 사용한다. 기본적으로 CPU의 1/4을 쓰게 된다.
    (하지만 커널 전체 추적이 활성화되었을 때, 모든 CPU를 사용한다.)

\--libmcount-single
:   빠른 데이터 기록을 위해서 libmcount의 단일 쓰레드 버전을 사용한다.
    대상 프로그램이  pthread 라이브러리와 연결되어 있는 경우에는 무시된다.

\--rt-prio=*PRIO*
:   *PRIO*를 우선순위로 사용하여, 기록 스레드 순위를 실시간(FIFO)로 향상시킨다.
    이 옵션은 특히 전체 커널 추적과 같은 환경에서 유용하다.

\--keep-pid
:   프로그램을 추적할 때  동일한 pid 값을 유지하게 해준다.
    일부 데몬 프로세스의 경우 분기 할 떄 동일한 pid를 갖는것이 중요하다.
    일반적으로 uftrace를 실행하면 fork()를 내부적으로 다시 호출하므로 
    pid가 변경된다. 이옵션을 사용할 경우 터미널 설정이 손상되는 경우가 있기 
    떄문에 `--no-pager` 옵션과 함께 사용하는 것이 좋다.

\--no-randomize-addr
:   ASLR(Address Space Layout Randomization)을 비활성화 한다.
    이는 프로세스의 라이브러리 로딩 주소가 매번 변경되지 않도록 막아준다.


REPLAY 옵션
==============
-f *FIELD*, \--output-fields=*FIELD*
:   결과 필드를 사용자가 지정한다. 가능한 값들로는 duration, tid, time,
    delta, elapsed, addr가 있다. 여러 필드는 콤마로 구분된다.
    모든 필드를 감추기 위한 (단일하게 사용되는) 'none' 특수 필드가 있다. 
    기본적으로 'duration,tid'가 사용된다. 

\--flat
:   C-형식이 아닌 플랫 형식으로 출력한다. 이 옵션은 주로 디버깅이나 테스트 용도로 사용된다.

\--column-view
:   열 별로 분리된 각각의 작업을 출력한다. 서로 다른 작업을 수행하는 함수의 구분을 돕는다.

\--column-offset=*DEPTH*
:   `--column-view` 옵션이 사용되었을 때, 이 옵션은 각 작업 사이의 오프셋 크기를 명시한다.
    기본 오프셋은 8이다.

\--task-newline
:   작업이 변경되면 새 줄을 추가한다.
    이를 통해 여러 작업에서 기능을 쉽게 구별 할 수 있다.

\--no-comment
:   리턴 함수에 대한 주석을 출력하지 않는다.

\--libname
:   함수 이름과 함께 라이브러리 이름을 출력한다.


공통 분석 옵션
=======================
\--kernel-full
:   사용자 함수 밖에서 호출된 모든 커널 함수를 보여준다.

\--kernel-only
:   사용자 함수를 제외한 커널 함수와 관련된 데이터만을 출력한다.

\--event-full
:   사용자 함수 밖의 모든 (사용자) 이벤트를 보여준다.

\--demangle=*TYPE*
:   필터, 트리거, 함수인자와 (또는) 반환 값을 디맹글(demangled)된 C++ 심볼
    이름으로 사용한다. "full", "simple" 그리고 "no" 값을 사용할 수 있다.
    함수인자와 템플릿 파라미터를 무시하는 "simple"이 기본이다.

-r *RANGE*, \--time-range=*RANGE*
:   시간 RANGE 내에 수행된 함수들만 표시한다. RANGE는 \<시작\>~\<끝\> ("~" 로
    구분) 이고 \<시작\>과 \<끝\> 중 하나는 생략 될 수 있다. \<시작\>과 \<끝\>
    은 타임스탬프 또는 '100us'와 같은 \<시간단위\>가 있는 경과 시간이다.
    `uftrace replay`(1)에서 `-f time` 또는 `-f elapsed`를 이용해 타임스탬프 또는
    경과 시간을 표시할 수 있다.


필터
=======
uftrace는 관심 대상이 아닌 함수들을 필터링한 결과들을 제공한다.
필터링은 유저들이 관심 있는 함수들에만 집중할 수 있게 하고,
데이터의 크기를 줄이기 때문에 사용이 권장된다.
uftrace가 호출되면, 두 종류의 함수 필터를 갖게 된다;
옵트인 필터로서의 `-F`/`--filter`와 옵트아웃 필터로서의 `-N`/`--notrace`.
이 필터들은 시간을 레코드하거나 리플레이할 떄 적용된다.

첫번째 필터 종류는 옵트인 필터이다. 기본적으로, 이것은 아무것도 추적하지 않는다.
하지만 어떤 명시된 함수가 실행되게 되면, 추적이 시작된다. 그러다 함수가 리턴하게 되면,
추적은 다시 멈추게 된다.   

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

일반적인 경우 uftrace는 `main()`부터 `c()`까지의 모든 함수들을 추적할 것이다.

    $ uftrace live ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
                [ 1234] |     b() {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

위 예시에서, 명시적으로 `live`명령어가 쓰였다. 하지만 `live`명령어는 기본 명령어이기 때문에
생략해도 무방하다. 따라서 위 명령어는 짧게 `uftrace ./abc`로 사용해도 같은 결과를 낸다.

하지만 `-F b` 필터 옵션이 사용되었을 때는, `main()`과 `a()`함수는 추적되지 않고 오직 `b()`과 `c()`만 
추적될 것이다.

    $ uftrace -F b ./abc
    # DURATION    TID     FUNCTION
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

두번째 필터 종류는 옵트아웃 필터이다. 기본적으로, 모든 것이 추적되지만,
명시된 함수가 실행되게 되면, 추적을 멈춘다. 제외된 함수가 리턴하게 되면, 추적을 재개한다. 

위 예시에서, `b()`함수와 그의 모든 호출은 `-N`옵션으로 생략할 수 있었다. 

    $ uftrace -N b ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

만일 특정 함수에만 관심이 있고 그 함수가 어떻게 호출되는지만 알고 싶다면,
caller filter를 사용하면 될 것이다. 그 함수를 leaf로 만들고,
그 함수의 모든 부모 함수들을 레코드한다.

    $ uftrace -C b ./abc
    # DURATION    TID     FUNCTION
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

위 예시에서, 호출 경로에 없는 함수들을 출력되지 않았다. 또한, 함수 `b()`의 자식 함수인 
함수 `c()`또한 출력되지 않았다. 

또한, `-D`옵션으로 함수의 중첩 깊이을 제한할 수도 있다.

    $ uftrace -D 3 ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

위 예시에서, uftrace는 함수 호출 깊이를 최대 3으로 제한하여 출력했기 때문에,
leaf 함수인 `c()`는 생략되었다. `-D`옵션이 `-F`옵션과 함께 쓰일 수 있음에 유의하라.

때로는, 장시간 실행되는 함수를 관찰하는 것이 유용하다. 
이는 작은 (실행시간을 가지는) 함수들 중에는 관심 대상이 아닌 것들이 많기 때문이다.
`-t`/`--time-filter`옵션은 명시된 임계시간보다 오래 실행된 함수들만 레코드할 수 있게 하는
시간 기반 필터이다. 위 예시에서는, 사용자는 대부분 아래와 같이 5마이크로 초 이상 동안 
실행되는 함수를 보고 싶어할 것이다:

    $ uftrace -t 5us ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

필터링된 함수에 트리거를 설정할 수도 있다. 더 많은 정보를 확인하기 위해 *TRIGGERS* 항목을
참고한다.

커널함수 추적을 설정하면, `@kernel` 식별자를 통해 커널 함수에 대한 필터를 적용할 수 있다.
이하 예시에서는 모든 유저 함수와 (커널 레벨의) page fault 핸들러들을 보여준다.

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


트리거
========
uftrace 도구는 선택된 함수 호출(필터가 있든 없든)과 
시그널에 대한 트리거 동작을 지원한다.
현재 지원되는 트리거와 사양에 대한 BNF는 다음과 같다.

    <trigger>    :=  <symbol> "@" <actions>
    <actions>    :=  <action>  | <action> "," <actions>
    <action>     :=  "depth="<num> | "backtrace" | "trace" | "trace_on" | "trace_off" |
                     "recover" | "color="<color> | "time="<time_spec> | "read="<read_spec> |
                     "finish" | "filter" | "notrace"
    <time_spec>  :=  <num> [ <time_unit> ]
    <time_unit>  :=  "ns" | "nsec" | "us" | "usec" | "ms" | "msec" | "s" | "sec" | "m" | "min"
    <read_spec>  :=  "proc/statm" | "page-fault" | "pmu-cycle" | "pmu-cache" | "pmu-branch"

`depth` 트리거는 함수를 실행하는 동안 필터 깊이를 변경한다.
다양한 함수에 대해 서로 다른 필터 깊이를 설정할 수 있다.
그리고 `backtrace` 트리거는 replay 시 스택 역추적을 출력한다.

색깔 트리거는 재생 명령어에서 색상을 변경한다.
지원되는 색상은 `red`, `green`, `blue`, `yellow`, `magenta`, `cyan`,`bold`,`gray`. 등이 있다.

다음 예제는 트리거 작동 방식을 보여준다. 전역 필터 깊이가 5로 설정되어 있지만
`b()` 함수에 `depth` 트리거를 설정하여 `b()` 아래 함수는 보이지 않게된다.

    $ uftrace -D 5 -T 'b@depth=1' ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

`backtrace` 트리거는 replay에서만 사용할 수 있다.

`trace_on`과 `trace_off` 트리거는 uftrace가 지정된 함수를 기록할지 여부를 관리한다.
또한, `_` 문자 없이 `traceon`과 `traceoff`로도 사용할 수있다.

`recover` 트리거는 프로세스가 콜스택에 직접 접근하는 일부 경우에 사용된다.
예를들어, v8 자바스크립트 엔진을 추적하는 동안 가비지 수집 단계에서 segfaults 
문제가 발생된다면 이는 v8이 (변경된) 반환 주소를 통해 컴파일된 코드 객체에 접근하려 하기 때문이다.
`recover` 트리거는 함수 시작점에 원래 반환 주소를 복원하고 기능 종료 시 
다시 uftrace 리턴 주소로 재설정한다. (특히 v8 자바스크립트 엔진 사례에서 `ExitFrame::Iterate` 
함수와 같이 문제를 발생시키는 상황에서 `recover` 사용하면 문제를 해결할 수 있다.)


`time` 트리거는 함수를 실행하는 동안 시간 필터 설정을 변경한다.
다른 함수들에 대해서 다른 시간 필터를 적용할 떄 사용할 수 있다.

`read` 트리거는 실행 시에 일부 정보를 읽을 수 있다. 
결과는 주어진 함수의 시작과 끝에 (내장) 이벤트의 형태로 기록된다.
현재는 다음과 같은 이벤트가 지원되고 있다.

 * "proc/statm": /proc 파일시스템에서 메모리 통계 처리 
 * "page-fault": getrusage(2)를 사용한 페이지 결함 수
 * "pmu-cycle":  Linux perf-event 시스템콜을 통한 cpu 클럭 사이클 및 명령어 실행 횟수
 * "pmu-cache":  (cpu) Linux Perfect-Event syscall을 사용한 캐시 참조 및 누락 
 * "pmu-branch": Linux Perfect-Event syscall을 사용한 분기 지침 및 누락
 
결과는 아래와 같이 이벤트(코멘트)로 출력된다.

    $ uftrace -T a@read=proc/statm ./abc
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


`finish` 트리거는 기록을 종료할 떄 사용한다. 데몬과 같이 종료되지 
않는 프로세스를 추적하는 데 유용할 수 있다.

`filter` 와 `notrace` 트리거는 각각 `-F`/`--filter`와 `-N` /`--notrace` 같은 효과가 있다.

트리거는 현재 유저 레벨 함수들에서만 동작한다.

트리거는 시그널에도 사용할 수 있다. `signal` 트리거에 의해 수행되며
`\--signal option` 옵션으로 함수 트리거와 비슷하지만
현재는 "trace_on", "trace_off" 및 "finish"트리거만 지원되고 있다.

    $ uftrace --signal 'SIGUSR1@finish' ./some-daemon


인자
=========
uftrace는 함수의 인자와 리턴값을 각각 -A/\--argument와 -R/\--retval로 레코딩할 수 있다.
이 문법체계는 트리거의 그것과 매우 유사하다:

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

-A/\--argument옵션은 symbol의 이름과 그것의 spec들을 선택적으로 받는다.
spec은 argN으로 시작되는데 여기서 N은 인자의 인덱스값이다.
인덱스는 1부터 시작되며, 순서는 시스템 호출 관례의 인자 전달 순서와 상응한다. 
인자의 인덱스는 정수형 (혹은 포인터형) 과 부동소수점형 각각 따로 세어진다는 점, 그리고 
그것들은 호출 관례에 따라 각기 간섭을 일으킬 수 있다는 점에 유의하라.
argN은 정수형 인자를, fpargN은 부동소수점형 인자를 위한 표기이다.

"d" 형식 혹은 아무 형식도 주지 않을 경우, uftrace는 정수형은 'long int'형으로 
간주하고 소수형에 대해서는 'double'형으로 간주한다.

"i" 형식은 signed 정수형으로, "u" 형식은 unsinged으로 출력한다.
두 형식 모두 10진수가 출력되는 한편 "x" 형식은 16진수로 출력되게 한다.
"s"는 null을 제외한 문자열 출력을 위한 형식이고, "c"는 단일 문자를 위한 형식이다.
"f" 형식은 부동 소수점을 출력하는데, (일반적으로) 리턴 값에서만 의미를 가진다. 

fpargN은 항상 소수점 방식이기 때문에 어떤 형식 필드도 없음에 유의하라.
"S" 형식은 std::string을 위한 형식이지만, 아직까지는 libstdc++ 라이브러리만 지원가능하다.
마지막으로, "p" 형식은 함수포인터 형식이다. 추적 대상의 주소가 레코드 되면, 언제나 함수 이름으로 
출력된다.

문자형 타입의 인자를 사용할 때 (포인터) 값이 유효하지 않을 경우 프로그램을 중단시킬 수 있음에 주의하라.
사실 uftrace는 유효한 프로세스 주소 공간의 범위를 지속적으로 추적하려 노력하지만, 
몇몇 코너 케이스들을 놓칠 수 있다.

또한 특정 레지스터의 이름이나 스택 오프셋도 인자로 명시할 수 있다 (리턴 값은 불가하다). 
이하 레지스터 이름들이 인자로 쓰일 수 있는 레지스터 이름들이다:

 * x86: rdi, rsi, rdx, rcx, r8, r9 (for integer), xmm[0-7] (for floating-point)
 * arm: r[0-3] (for integer), s[0-15] or d[0-7] (for floating-point)

예시는 아래와 같다:

    $ uftrace -A main@arg1/x -R main@retval/i32 ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main(0x1) {
                [ 1234] |   a() {
                [ 1234] |     b() {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } = 0; /* main */

    $ uftrace -A puts@arg1/s -R puts@retval ./hello
    Hello world
    # DURATION    TID     FUNCTION
       1.457 us [21534] | __monstartup();
       0.997 us [21534] | __cxa_atexit();
                [21534] | main() {
       7.226 us [21534] |   puts("Hello world") = 12;
       8.708 us [21534] | } /* main */

이 인자들과 리턴값들은 실행파일이 `-pg`옵션으로 빌드되었을 때에만 레코드됨에 유의하라.
`-finstrument-functions`로 만들어진 실행파일들은 라이브러리 호출을 제외하고는 무시된다.
인자와 리턴값의 레코드는 아직까진 사용자 정의 함수에서만 동작한다.

만일 프로그램이 DWARF와 같은 디버그 정보와 함께 빌드되었다면, uftrace는 (libdw로 빌드되었다면) 자동으로  
인자들의 갯수와 자료형들을 식별할 수 있다. 또한 디버그 정보를 사용하지 않더라도, 몇몇 잘 알려진 
라이브러리 함수들의 인자들과 리턴값은 기본적으로 제공된다. 
이 경우 사용자는 인자들의 spec과 리턴값을 수동적으로 명시할 필요가 없다 - 그저 함수의 이름 (또는 패턴) 만 
주는 것으로도 충분하다. 사실, 명시적으로 argspec 을 지정하면 자동 argspec을 표시되지 않게 한다. 

예를 들어, 위 예시는 아래와 같이 작성할 수 있다.

    $ uftrace -A . -R main -F main ./hello
    Hello world
    # DURATION     TID     FUNCTION
                [ 18948] | main(1, 0x7ffeeb7590b8) {
       7.183 us [ 18948] |   puts("Hello world");
       9.832 us [ 18948] | } = 0; /* main */

인자 패턴 (".")은 모든 문자에 대응되기 때문에 모든 (지원되는) 함수들이 레코드 되었음에 유의하라.
"main"함수의 두 인자들과 "puts"의 한 문자열 인자를 보여준다.
만일 모든 (지원되는) 함수의 모든 인자들과 리턴값들을 보고 싶다면, -a/\--auto-args 옵션을 사용하라.


필드
======
uftrace 이용자는 replay 결과를 몇몇 필드로 커스터마이징할 수 있다. 
여기서 필드란 파이프 문자 (|) 왼쪽에 나타나는 정보를 뜻한다.
기본적으로 지속시간과 tid필드를 사용하지만, 다른 필드들도 다음과 같이 임의의 순서로 이용 가능하다:

    $ uftrace -f time,delta,duration,tid,addr ./abc
    #     TIMESTAMP      TIMEDELTA  DURATION    TID      ADDRESS     FUNCTION
        75059.205379813              1.374 us [27804]       4004d0 | __monstartup();
        75059.205384184   4.371 us   0.737 us [27804]       4004f0 | __cxa_atexit();
        75059.205386655   2.471 us            [27804]       4006b1 | main() {
        75059.205386838   0.183 us            [27804]       400656 |   a() {
        75059.205386961   0.123 us            [27804]       400669 |     b() {
        75059.205387078   0.117 us            [27804]       40067c |       c() {
        75059.205387264   0.186 us   0.643 us [27804]       4004b0 |         getpid();
        75059.205388501   1.237 us   1.423 us [27804]       40067c |       } /* c */
        75059.205388724   0.223 us   1.763 us [27804]       400669 |     } /* b */
        75059.205388878   0.154 us   2.040 us [27804]       400656 |   } /* a */
        75059.205389030   0.152 us   2.375 us [27804]       4006b1 | } /* main */

각 필드들은 다음과 같은 의미를 가진다:

 * tid: 작업 id (gettid(2)로 얻을 수 있다.)
 * duration: 함수 실행 시간
 * time: 실행 시각
 * delta: 어떤 작업 내 두 timestamp의 차이 
 * elapsed: 첫 timestamp로부터의 경과 시간
 * addr: 해당 함수의 주소
 * task: 작업 이름 (comm)
 * module: 라이브러리 혹은 실행 가능한 함수의 이름

기본적으로 설정된 필드값은 'duration, tid'이다. 만약 주어진 필드의 이름이 "+"로 시작된다면,
그 필드는 기본 필드값에 추가될 것이다. 즉, "-f +time"는 "-f duration,tid,time"와 같은 것이다.
또한 'none'이라는 특별한 필드도 받을 수 있는데, 
이는 필드 출력을 하지 않고 오직 함수 실행 결과만을 보여준다.


동적 추적
===============
uftrace는 x86_64, AArch64환경의 런타임 (정확하게는, 로드타임) 에서 동적인 함수 추적이 가능하다.
함수를 레코드하기 전에, 보통 프로그램을 `-pg` (혹은
`-finstrument-functions`으로) 빌드해야 하고, 그렇게 된다면 모든 함수들이 `mcount()`를
호출하기 때문에 어느 정도 성능에 영향을 받게 될 것이다.

동적인 추적을 할 때, `-P`/`--patch` 옵션을 통해 특정 함수만을 추적할 수 있다.
capstone disassembly engine을 사용한다면 위 옵션을 지정해서 프로그램을 (재)컴파일할 필요가 없다.

이제 uftrace는 명령어들을 분석할 수 있게 되고 (만약 가능하다면) 그 명령어들을 
다른 곳에 복사하여 `mcount()`함수들을 호출하여 uftrace로 추적할 수 있게 rewrite 할 수 있다.
그 이후 제어권은 복사된 명령어로 넘어가게 되고, 그 다음에야 남은 명령어들로 리턴하게 된다.

capstone을 사용할 수 없다면, 프로그램을 빌드할 때 몇몇 컴파일러 (gcc) 옵션들을 추가해야 할 것이다.
gcc 5.1 버전 이상부터 `-mfentry`와 `-mnop-mcount`옵션을 제공하는데 
이 옵션들은 함수 맨 앞에 인스트루먼테이션 (이를테면, `mcount()` 함수를 호출하는) 코드를 추가하고 
그 명령어를 NOP로 변환한다. 그렇게 되면 정상적인 조건에서 실행한다면 성능 상의 오버헤드가 거의 없어질 것이다.
uftrace는 `-P`옵션을 이용하여 선택적으로 `mcount()`함수를 호출할 수 있게 전환할 수 있다.

uftrace를 이하 예제에서 평소처럼 사용한다면 에러 메세지를 띄운다.
그 이유는 바이너리가 어떤 인스트루먼테이션 코드 (이를테면 `mcount()`함수)도 호출하지 않기 때문이다.

    $ gcc -o abc -pg -mfentry -mnop-mcount tests/s-abc.c
    $ uftrace abc
    uftrace: /home/namhyung/project/uftrace/cmd-record.c:1305:check_binary
      ERROR: Can't find 'mcount' symbol in the 'abc'.
             It seems not to be compiled with -pg or -finstrument-functions flag
             which generates traceable code.  Please check your binary file.

하지만 `-P a` 패치 옵션을 적용한다면, 동적으로 `a()` 함수만을 추적할 것이다. 

    $ uftrace --no-libcall -P a abc
    # DURATION    TID     FUNCTION
       0.923 us [19379] | a();

추가로, '.'을 이용해 (glob은, '*') `P`옵션과 함께 정규표현식으로 쓰인 문자에 대해  
하나라도 매칭되는 모든 함수들에 대해서도 적용시킬 수 있다.

    $ uftrace --no-libcall -P . abc
    # DURATION    TID     FUNCTION
                [19387] | main() {
                [19387] |   a() {
                [19387] |     b() {
       0.940 us [19387] |       c();
       2.030 us [19387] |     } /* b */
       2.451 us [19387] |   } /* a */
       3.289 us [19387] | } /* main */

Clang/LLVM 4.0은 [X-ray](http://llvm.org/docs/XRay.html)라는 동적인 인스트루먼테이션 기술을 제공한다.
이는 `gcc -mfentry -mnop-mcount`와 `-finstrument-functions`를 결합한 것과도 유사하다.
uftrace는 `X-ray`로 빌드된 실행파일에 대해서도 동적인 추적을 지원한다.

예를 들어, 대상 프로그램을 clang으로 아래의 옵션으로 빌드할 수도 있지만,
그와 동일하게 동적인 추적을 위해 아래와 같이 `-P`옵션을 사용할 수도 있을 것이다:

    $ clang -fxray-instrument -fxray-instruction-threshold=1 -o abc-xray  tests/s-abc.c
    $ uftrace -P main abc-xray
    # DURATION    TID     FUNCTION
                [11093] | main() {
       1.659 us [11093] |   getpid();
       5.963 us [11093] | } /* main */

    $ uftrace -P . abc-xray
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


스크립트 실행
================
uftrace는 함수의 진입과 종료를 보여주는 스크립트 실행을 지원한다.
지원되는 스크립트는 아직까지는 Python 2.7 뿐이다.

사용자는 네 개의 함수를 쓸 수 있다. 'uftrace_entry'와 'uftracce_exit'은 
각 함수가 진입과 종료시기에서 실행 중이라면 언제든 실행된다.
하지만 'uftrace_begin'과 'uftrace_end'는 분석 대상 프로그램이 시작되고 끝날 때 한 번씩만 실행된다.

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

위 스크립트는 아래와 같이 레코드 시간 순으로 실행될 수 있다:

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

'ctx'변수는 아래의 정보를 포함하는 딕셔너리 변수이다.

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

'script_context'에 있는 각 필드들은 스크립트 내에서 읽을 수 있다.
스크립팅에 대한 자세한 사항은 `uftrace-script`(1)를 참고할 것.


조사식
===========
uftrace의 watch point는 특정 값의 변경사항을 출력한다. 개념적으로는 디버거의 watch point와 같지만,
함수의 진입과 종료에만 적용되기 때문에 몇몇 변경사항들은 놓칠 수도 있다.

아직까지는, 아래의 watch point들이 지원된다:

 * "cpu" : 현재 작업을 수행하는 cpu 번호

트리거를 읽을 때처럼, 결과는 이벤트로서 (주석으로) 출력된다:

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
========
`uftrace-record`(1), `uftrace-replay`(1), `uftrace-report`(1), `uftrace-script`(1)


번역자
======
강민철 <tegongkang@gmail.com>
김관영 <@gmail.com>
