% UFTRACE-REPLAY(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace-replay - 기록된 데이터의 함수 실행 흐름을 출력한다.


사용법
======
uftrace replay [*options*]


설명
====
이 명령어는 `uftrace-record`(1) 명령어를 통해 기록된 데이터의 함수 실행 흐름을
출력한다.  출력되는 함수들은 C 프로그램과 유사한 형식으로 시간 순서대로 출력된다.


REPLAY 옵션
==============
-f *FIELD*, \--output-fields=*FIELD*
:   결과로 보여지는 필드를 사용자가 지정한다. 가능한 값들로는 duration, tid,
    time, delta, elapsed, addr 가 있다.  여러 필드를 갖는 경우 콤마로 구분된다.
    모든 필드를 감추기 위한 (단일하게 사용되는) 'none' 특수 필드가 있으며
    기본적으로 'duration,tid' 가 사용된다.  상세한 설명은 *FIELDS* 를 참고한다.

\--flat
:   C 와 같이 호출 깊이가 보이는 방식이 아닌 평평한(flat) 형식으로 출력한다.
    이 옵션은 주로 디버깅이나 테스트 용도로 사용된다.

\--column-view
:   열(column) 별로 분리하여 각각의 태스크를 출력한다.  서로 다른 태스크에서
    실행하는 함수의 구분을 쉽게한다.

\--column-offset=*DEPTH*
:   `--column-view` 옵션이 사용되었을 때, 이 옵션은 각 태스크 사이의
    간격(offset) 크기를 명시한다.  기본 간격은 8 이다.

\--task-newline
:   태스크가 변경되면 빈 공백 한줄을 추가한다.
    이를 통해 여러 태스크에서 동작하는 함수들을 쉽게 구별 할 수 있다.

\--no-comment
:   함수가 반환되는 곳에 주석을 출력하지 않는다.

\--libname
:   함수 이름과 함께 라이브러리 이름을 출력한다.


공통 옵션
=========
-F *FUNC*, \--filter=*FUNC*
:   선택된 함수들(그리고 그 내부의 함수들)만 출력하도록 필터를 설정한다.
    이 옵션은 한번 이상 쓰일 수 있다.
    필터에 대한 설명은  *FILTERS* 를 참고한다.

-N *FUNC*, \--notrace=*FUNC*
:   선택된 함수들 (또는 그 아래 함수들)을 출력에서 제외하도록 설정하는 옵션이다.
    이 옵션은 한번 이상 쓰일 수 있다.
    필터에 대한 설명은 *FILTERS* 를 참고한다.

-H *FUNC*, \--hide=*FUNC*
:   주어진 FUNC 함수들을 출력 대상에서 제외할 수 있다.  이는 선택된 함수의 자식
    함수들에 대해서는 영향을 주지 않으며 단지 주어진 함수들만 숨기는 기능을 하게
    된다. 이 옵션은 한번 이상 쓰일 수 있다.

-C *FUNC*, \--caller-filter=*FUNC*
:   선택된 함수의 호출자를 출력하는 필터를 설정한다. 이 옵션은 한번 이상 쓰일 수 있다.
    필터에 대한 설명은 *FILTERS* 를 참고한다.


-T *TRG*, \--trigger=*TRG*
:   선택된 함수의 트리거를 설정한다. 이 옵션은 한번 이상 쓰일 수 있다.
    트리거에 대한 설명은 *TRIGGERS* 를 참고한다.

-D *DEPTH*, \--depth=*DEPTH*
:   함수가 중첩될 수 있는 최대 깊이를 설정한다.
    (이를 넘어서는 상세한 함수 실행과정은 무시한다.)
    필터에 대한 설명은 *FILTERS* 를 참고한다.

-t *TIME*, \--time-filter=*TIME*
:   설정한 시간 이하로 수행된 함수는 표시하지 않게 한다. 만약 어떤 함수가
    명시적으로 'trace' 트리거가 적용된 경우, 그 함수는 실행 시간과 상관없이 항상
    출력된다. 필터에 대한 설명은 *FILTERS* 를 참고한다.

\--no-libcall
:   라이브러리 호출은 표시하지 않게 한다.

\--no-event
:   이벤트는 표시하지 않게 한다.

\--match=*TYPE*
:   타입(TYPE)으로 일치하는 패턴을 보여준다. 가능한 형태는 `regex`와 `glob`이다.
    기본 설정은 `regex`이다.

\--disable
:   uftrace 를 시작할때 데이터를 기록하지 않고 시작한다.
    이것은 `trace_on` 트리거와 함께 사용되었을 때만 의미를 가진다.


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

    $ uftrace ./abc
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
아래의 예는 필터가 `uftrace replay`를 할때 적용되었음에 유의하라.

    $ uftrace record ./abc
    $ uftrace replay -F b
    # DURATION    TID     FUNCTION
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

두번째 필터 종류는 선택하지 않는 방식의 필터이다.  기본적으로, 모든 것이
추적되지만, 명시된 함수에 진입하게 되면, 추적을 멈춘다.  제외된 함수가 반환하게
되면, 추적을 재개한다.

위 예시에서, `b()` 함수와 그의 모든 하위 함수들의 호출은 `-N` 옵션으로 제외할 수 있다.

    $ uftrace record ./abc
    $ uftrace replay -N b
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

`b()` 함수만을 숨기고 그의 하위 함수들은 그대로 보고 싶으면 `-H` 옵션을 사용할 수 있다.

    $ uftrace record ./abc
    $ uftrace replay -H b
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       3.880 us [ 1234] |     c();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

위의 `-H` 옵션은 특히 C++ 프로그램에서 `-H ^std::` 와 같이 사용해서
std 네임스페이스의 호출들을 숨길때 유용하다.

만일 특정 함수에만 관심이 있고 그 함수가 어떻게 호출되는지만 알고 싶다면,
caller filter 를 사용하면 될 것이다. 그 함수를 마지막(leaf) 노드로 만들고,
그 함수의 모든 부모 함수들을 기록한다.

    $ uftrace record ./abc
    $ uftrace replay -C b
    # DURATION    TID     FUNCTION
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

위 예시에서, 호출 경로에 없는 함수들을 출력되지 않았다. 또한, 함수 `b()`의 자식 함수인
함수 `c()` 또한 출력되지 않았다.

또한, `-D` 옵션으로 함수의 중첩 깊이을 제한할 수도 있다.

    $ uftrace record ./abc
    $ uftrace replay -D 3
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

    $ uftrace record ./abc
    $ uftrace replay -t 5us
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

동일한 데이터에 대해 다른 시간 필터 값을 설정해 replay 결과를 확인할 수 있다.

    $ uftrace replay -t 6us
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

또한, `-r` 옵션은 주어진 시간 범위 동안 실행된 함수들을 보여준다.
이 옵션을 사용할 때, 결과값을 TIMESTAMP, ELAPSED, DURATION, TID 필드들과 함께 볼 수 있다.

    $ uftrace replay -r 502716.387320101~502716.387322389
    #     TIMESTAMP      DURATION    TID     FUNCTION
    502716.387320101   0.289 us [ 6126] |   fgets();
    502716.387320584            [ 6126] |   get_values_from() {
    502716.387320709   0.245 us [ 6126] |     strdup();
    502716.387321172   0.144 us [ 6126] |     strsep();
    502716.387321542   0.223 us [ 6126] |     atoi();
    502716.387321983   0.239 us [ 6126] |     atoi();
    502716.387322389   1.805 us [ 6126] |   } /* get_values_from */

    $ uftrace replay -r 40us~ | head -10
    #  ELAPSED   DURATION    TID     FUNCTION
      40.141 us            [ 6126] |   get_values_from() {
      40.269 us   0.249 us [ 6126] |     strdup();
      40.756 us   0.149 us [ 6126] |     strsep();
      41.119 us   0.235 us [ 6126] |     atoi();
      41.578 us   0.211 us [ 6126] |     atoi();
      41.957 us   1.816 us [ 6126] |   } /* get_values_from */
      42.124 us   0.220 us [ 6126] |   fgets();
      42.529 us            [ 6126] |   get_values_from() {
      42.645 us   0.236 us [ 6126] |     strdup();

필터링된 함수에 트리거를 설정할 수도 있다.  더 많은 정보는 *TRIGGERS* 항목에서
참고할 수 있다.


TRIGGERS
========
uftrace 는 (필터가 있든 없든) 선택된 함수 호출에 대한 트리거 동작을 지원한다.
현재 지원되는 트리거와 사양에 대한 BNF 는 다음과 같다.

    <trigger>    :=  <symbol> "@" <actions>
    <actions>    :=  <action>  | <action> "," <actions>
    <action>     :=  "depth="<num> | "backtrace" | "trace_on" | "trace_off" |
                     "color="<color> | "time="<time_spec> | "filter" | "notrace" | "hide"
    <time_spec>  :=  <num> [ <time_unit> ]
    <time_unit>  :=  "ns" | "nsec" | "us" | "usec" | "ms" | "msec" | "s" | "sec" | "m" | "min"

`depth` 트리거는 함수를 실행하는 동안 필터의 깊이를 변경한다.  다양한 함수에 대해
서로 다른 필터 깊이를 설정할 수 있다.  그리고 `backtrace` 트리거는 replay 시 스택
백트레이스를 출력한다.

`color` 트리거는 색상을 변경한다.  지원되는 색상은 `red`, `green`, `blue`,
`yellow`, `magenta`, `cyan`, `bold`, `gray` 가 있다.

다음 예제는 트리거의 작동 방식을 보여준다.  함수 `b()`에 `backtrace` action 을 넣고
필터 깊이를 2 로 설정한다.

    $ uftrace record ./abc
    $ uftrace replay -T 'b@filter,backtrace,depth=2'
    # DURATION    TID     FUNCTION
      backtrace [ 1234] | /* [ 0] main */
      backtrace [ 1234] | /* [ 1] a */
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

`trace_on`과 `trace_off` 트리거는 uftrace 가 지정된 함수를 기록할지 여부를
관리한다.  또한, `_` 문자 없이 `traceon` 과 `traceoff` 로도 사용할 수 있다.

`time` 트리거는 함수를 실행하는 동안 시간 필터(time-filter) 설정을 변경한다.
다른 함수들에 대해서 서로 다른 시간 필터를 적용할 떄 사용할 수 있다.

`filter` 와 `notrace` 트리거는 각각 `-F`/`--filter` 와 `-N` /`--notrace` 같은
효과가 있다.

`hide` 트리거는 특정 함수를 보이지 않게 하는 `-H`/`--hide` 옵션과 같은 효과가
있어서 `notrace` 와 다르게 하위 함수들에 대해서는 적용되지 않는다.


FIELDS
======
uftrace 사용자는 replay 결과를 몇몇의 필드로 원하는 방식대로 구성할 수 있다.
여기서 필드란 파이프 문자 (|) 왼쪽에 나타나는 정보를 뜻한다.
기본적으로 지속시간 duration 과 tid 필드를 사용하지만, 다른 필드들도 다음과 같이
임의의 순서로 사용 가능하다.

    $ uftrace replay -f time,delta,duration,addr
    #     TIMESTAMP      TIMEDELTA  DURATION     ADDRESS     FUNCTION
        74469.340757350              1.583 us       4004d0 | __monstartup();
        74469.340762221   4.871 us   0.766 us       4004f0 | __cxa_atexit();
        74469.340764847   2.626 us                  4006b1 | main() {
        74469.340765061   0.214 us                  400656 |   a() {
        74469.340765195   0.134 us                  400669 |     b() {
        74469.340765344   0.149 us                  40067c |       c() {
        74469.340765524   0.180 us   0.742 us       4004b0 |         getpid();
        74469.340766935   1.411 us   1.591 us       40067c |       } /* c */
        74469.340767195   0.260 us   2.000 us       400669 |     } /* b */
        74469.340767372   0.177 us   2.311 us       400656 |   } /* a */
        74469.340767541   0.169 us   2.694 us       4006b1 | } /* main */

각 필드들은 다음과 같은 의미를 가진다.

 * tid: task id (gettid(2)로 얻을 수 있다.)
 * duration: 함수 실행 시간
 * time: 타임스탬프 정보
 * delta: 어떤 작업 내 두 타임스탬프의 차이
 * elapsed: 첫 타임스탬프로부터의 경과 시간
 * addr: 해당 함수의 주소
 * task: 태스크 이름 (comm)
 * module: 라이브러리 혹은 실행 가능한 함수의 이름

기본적으로 설정된 필드값은 'duration,tid'이다.  만약 주어진 필드의 이름이 "+"로
시작된다면, 그 필드는 기본 필드값에 추가될 것이다.  즉, "-f +time" 는
"-f duration,tid,time" 와 같은 것이다.  또한 'none'이라는 특별한 필드도 받을 수
있는데, 이는 필드 출력을 하지 않고 오직 함수 실행 결과만을 보여준다.


함께 보기
=========
`uftrace`(1), `uftrace-record`(1), `uftrace-report`(1), `uftrace-info`(1)


번역자
======
강민철 <tegongkang@gmail.com>, 김홍규 <honggyu.kp@gmail.com>
