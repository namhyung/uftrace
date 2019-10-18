% UFTRACE-REPLAY(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace-replay - 레코드된 함수 추적 정보를 출력한다


사용법
========
uftrace replay [*옵션*]


설명
===========
이 명령어는 `uftrace-record`(1)명령어를 통해 레코드된 추적 데이터를 출력한다.
추적된 함수는 시간 순서대로 C 프로그램 형식으로 출력된다.


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


공통 분석 옵션
=======================
\--kernel-full
:   사용자 함수 밖에서 호출된 모든 커널 함수를 보여준다.

\--kernel-only
:   사용자 함수를 제외한 커널 함수와 관련된 데이터만을 출력한다.

\--event-full
:   사용자 함수 밖의 모든 (사용자) 이벤트를 보여준다.   

\--tid=*TID*[,*TID*,...]
:   Only print functions called by the given threads.  To see the list of
    threads in the data file, you can use `uftrace report --threads` or
    `uftrace info`.  This option can also be used more than once.

\--demangle=*TYPE*
:   필터, 트리거, 함수인자와 (또는) 반환 값을 디맹글(demangled)된 C++ 심볼
    이름으로 사용한다. "full", "simple" 그리고 "no" 값을 사용할 수 있다.
    함수인자와 템플릿 파라미터를 무시하는 "simple"이 기본이다.

-r *RANGE*, \--time-range=*RANGE*
:   시간 RANGE 내에 수행된 함수들만 표시한다. RANGE는 \<시작\>~\<끝\> ("~" 로
    구분) 이고 \<시작\>과 \<끝\> 중 하나는 생략 될 수 있다. \<시작\>과 \<끝\>
    은 타임스탬프 또는 '100us'와 같은 \<시간단위\>가 있는 경과 시간이다.
    `uftrace replay`(1)에서 `-f time` 또는 `-f elapsed`를 이용해 타임스탬프 또는
    경과 시간을 표시할 수 있다. *필터*항목을 참고하라.


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


함께 보기
========
`uftrace`(1), `uftrace-record`(1), `uftrace-report`(1), `uftrace-info`(1)


번역자
========
강민철 tegongkang@gmail.com