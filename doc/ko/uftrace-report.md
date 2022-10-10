% UFTRACE-REPORT(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

이름
====
uftrace-report - 기록된 데이터의 통계와 요약 정보를 출력한다.


사용법
======
uftrace report [*options*]


설명
====
이 명령어는 주어진 데이터 파일의 데이터를 모으고 그 요약 정보와 통계 자료들을 출력한다.
기본적으로 함수자료들을 보여주는데, `--task` 옵션을 통해 실행한 태스크 단위의  통계자료를
볼 수 있고, `--diff` 옵션은 추가 인자로 데이터를 입력하면, 그 데이터와 원본 데이터 간의
차이점을 보여준다.


REPORT 옵션
===========
-f *FIELD*, \--output-fields=*FIELD*
:   결과로 보여지는 필드를 사용자가 지정한다.  가능한 값들로는 `total`, `total-avg`,
    `total-min`, `total-max`, `self`, `self-avg`, `self-min`, `self-max`, `size` 그리고
    `call`이 있다.  여러 필드를 갖는 경우 콤마로 구분된다.
    모든 필드를 감추기 위한 (단일하게 사용되는) 'none' 특수 필드가 있으며
    기본적으로 'total,self,call' 이 사용된다.  상세한 설명은 *FIELDS* 를 참고한다.

-s *KEYS*[,*KEYS*,...], \--sort=*KEYS*[,*KEYS*,...]
:   주어진 키를 기반으로 함수들을 정렬한다. 여러 키들을 적용할 경우, 키들을 쉼표(,)로 나누어 표현한다.
    `total` (time), `total-avg`, `total-min`, `total-max`, `self` (time), `self-avg`, `self-min`,
    `self-max`, `size`, `call`, `func`를 키로 이용할 수 있다. 그러나 `--avg-total` 또는 `--avg-self`
    옵션이 사용된 경우, 총 시간(total time) 또는 자체 시간(self time에)에 적용되는
    `avg`, `min`, `max`를 키로 이용할 수 있다.

\--avg-total
:   각 함수의 총 시간(total time)의 평균, 최소, 최대 시간을 보여준다.

\--avg-self
:   각 함수의 자체 시간(self time)의 평균, 최소, 최대 시간을 보여준다.

\--task
:   함수의 통계자료가 아닌 태스크를 요약해서 보고한다.
    -f 옵션을 이용해 출력 필드를 사용자가 지정할 수 있다.
    가능한 값들로는: `total`, `self`, `func` 그리고 `tid`가 있다.
    여러 필드를 갖는 경우 콤마로 구분된다. 모든 필드를 감추기 위한
    (단일하게 사용되는) 'none' 특수 필드가 있으며 기본적으로 'total,self,func,tid' 가 사용된다.
    상세한 설명은 *FIELDS* 를 참고한다.

\--diff=*DATA*
:   입력한 추적 데이터와 주어진 데이터의 차이점을 보고한다. 두 데이터는 uftrace 로
    record 한 데이터이며, 데이터를 담은 디렉토리를 인자로 넘겨야한다.

\--diff-policy=*POLICY*
:   `--diff`옵션을 사용할 때, 사용자가 지정한 diff 정책을 적용한다. 사용가능한 값으로는
    "abs", "no-abs", "percent", "no-percent", "compact" "full"이 있다. "abs"는 절대값을
    사용하여 diff 결과를 정렬하며 양수와 음수 항목을 함께 표시할 수 있다. "no-abs"는
    먼저 양수 항목을 표시한 다음 음수 항목을 표시한다. "percent"는 diff를 백분율로 표시하고
    "no-percent"는 값으로 표시한다. "full"은 기준, 새 데이터, 차이점 이 세 열을 모두 표시하는
    반면 "compact"는 차이점만 표시한다. 기본값은 "abs", "compact", "no-percent"다.

\--sort-column=*IDX*
:   `--diff`를 "full" 정책과 함께 사용할 때, 총 시간, 자체 시간, 호출 횟수 이 3개의 열이
    표시된다. 이 옵션은 정렬 키로 사용할 열 인덱스를 선택한다. 인덱스 0은 `--data`옵션으로
    제공되는 원본 데이터에 대한 것이고, 인덱스 1은 `--diff`옵션으로 제공되는 데이터에 대한 것,
    인덱스 2는 두 데이터 간의 (백분율) 차이에 대한 것이다.

\--srcline
:   가능한 각 함수들의 소스 줄번호를 표시한다.

\--format=*TYPE*
:   형식화된 출력을 보여준다. 현재는 'normal' 과 'html' 형식이 지원된다.


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
:   이벤트들을 표시하지 않게 한다.  `--no-sched` 옵션을 내포한다.

\--no-sched
:   스케줄 이벤트를 표시하지 않게 한다.

\--no-sched-preempt
:   선점 스케줄 이벤트는 표시하지 않게 하나
    일반(대기) 스케쥴 이벤트는 그대로 표시한다.

\--match=*TYPE*
:   타입(TYPE)으로 일치하는 패턴을 보여준다. 가능한 형태는 `regex`와 `glob`이다.
    기본 설정은 `regex`이다.


공통 분석 옵션
=======================
-H *FUNC*, \--hide=*FUNC*
:   주어진 FUNC 함수들을 출력 대상에서 제외할 수 있다.  이는 선택된 함수의 자식
    함수들에 대해서는 영향을 주지 않으며 단지 주어진 함수들만 숨기는 기능을 하게
    된다. 이 옵션은 한번 이상 쓰일 수 있다.

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
이 명령어는 아래와 같은 정보들을 출력한다.

    $ uftrace record abc
    $ uftrace report
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================
      150.829 us  150.829 us           1  __cxa_atexit
       27.289 us    1.243 us           1  main
       26.046 us    0.939 us           1  a
       25.107 us    0.934 us           1  b
       24.173 us    1.715 us           1  c
       22.458 us   22.458 us           1  getpid

    $ uftrace report -s call,self
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================
      150.829 us  150.829 us           1  __cxa_atexit
       22.458 us   22.458 us           1  getpid
       24.173 us    1.715 us           1  c
       27.289 us    1.243 us           1  main
       26.046 us    0.939 us           1  a
       25.107 us    0.934 us           1  b

    $ uftrace report --avg-self
        Avg self    Min self    Max self  Function
      ==========  ==========  ==========  ====================
      150.829 us  150.829 us  150.829 us  __cxa_atexit
       22.458 us   22.458 us   22.458 us  getpid
        1.715 us    1.715 us    1.715 us  c
        1.243 us    1.243 us    1.243 us  main
        0.939 us    0.939 us    0.939 us  a
        0.934 us    0.934 us    0.934 us  b

    $ uftrace report --task
      Total time   Self time   Num funcs     TID  Task name
      ==========  ==========  ==========  ======  ================
       22.178 us   22.178 us           7   29955  t-abc

    $ uftrace record --srcline abc
    $ uftrace report --srcline
      Total time   Self time       Calls  Function [Source]
      ==========  ==========  ==========  ====================
       17.508 us    2.199 us           1  main [./tests/s-abc.c:26]
       15.309 us    2.384 us           1  a [./tests/s-abc.c:11]
       12.925 us    2.633 us           1  b [./tests/s-abc.c:16]
       10.292 us    5.159 us           1  c [./tests/s-abc.c:21]
        5.133 us    5.133 us           1  getpid
        3.437 us    3.437 us           1  __monstartup
        1.959 us    1.959 us           1  __cxa_atexit

두 데이터의 차이점을 보려면:

    $ uftrace record abc

    $ uftrace report --diff uftrace.data.old
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record abc )
    #  [1] diff: uftrace.data.old   (from uftrace record abc )
    #
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================
       -0.301 us   -0.038 us          +0  main
       -0.263 us   -0.070 us          +0  a
       -0.193 us   -0.042 us          +0  b
       -0.151 us   -0.090 us          +0  c
       -0.131 us   -0.131 us          +0  __cxa_atexit
       -0.061 us   -0.061 us          +0  getpid

위의 예제는 총 시간의 절대값으로 정렬한 두 데이터의 차이점들을 보여준다.
아래의 예제는 자체 시간의 (부호가 있는) 값을 이용해 정렬했다.

    $ uftrace report --diff uftrace.data.old -s self --diff-policy no-abs
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record abc )
    #  [1] diff: uftrace.data.old   (from uftrace record abc )
    #
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================
       -0.301 us   -0.038 us          +0  main
       -0.193 us   -0.042 us          +0  b
       -0.061 us   -0.061 us          +0  getpid
       -0.263 us   -0.070 us          +0  a
       -0.151 us   -0.090 us          +0  c
       -0.131 us   -0.131 us          +0  __cxa_atexit

"full" 정책을 사용하면 사용자는 아래와 같은 원시(raw) 데이터를 볼 수 있다.
또한 (원시 데이터의 경우) 다른 열로 정렬도 가능하다.
밑의 예제는 base 데이터의 총 시간을 기준으로 결과를 정렬한다.

    $ uftrace report --diff uftrace.data.old --sort-column 0 --diff-policy full,percent
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record abc )
    #  [1] diff: uftrace.data.old   (from uftrace record abc )
    #
                     Total time (diff)                   Self time (diff)                  Nr. called (diff)   Function
      ================================   ================================   ================================   ====================
        2.812 us    2.511 us   -10.70%     0.403 us    0.365 us    -9.43%            1          1         +0   main
        2.409 us    2.146 us   -10.92%     0.342 us    0.272 us   -20.47%            1          1         +0   a
        2.067 us    1.874 us    -9.34%     0.410 us    0.368 us   -10.24%            1          1         +0   b
        1.657 us    1.506 us    -9.11%     0.890 us    0.800 us   -10.11%            1          1         +0   c
        0.920 us    0.789 us   -14.24%     0.920 us    0.789 us   -14.24%            1          1         +0   __cxa_atexit
        0.767 us    0.706 us    -7.95%     0.767 us    0.706 us    -7.95%            1          1         +0   getpid


FIELDS
======
uftrace 사용자는 report 결과를 몇몇의 필드로 원하는 방식대로 구성할 수 있다.
기본적으로 total, self와 call 필드를 사용하지만, 다른 필드들도 다음과 같이
임의의 순서로 사용 가능하다.

    $ uftrace report -f total,total-max,self-min,call
    Total time   Total max    Self min       Calls  Function
    ==========  ==========  ==========  ==========  ====================
     97.234 us   36.033 us    1.073 us           3  lib_a
     50.552 us   26.690 us    2.828 us           2  lib_b
     46.806 us   46.806 us    3.290 us           1  main
     43.516 us   43.516 us    7.483 us           1  foo
     32.010 us   20.847 us    9.684 us           2  lib_c

각 필드는 아래와 같이 정렬 키로도 사용될 수 있다.

    $ uftrace report -f total,total-max,self-min,call -s call
    Total time   Total max    Self min       Calls  Function
    ==========  ==========  ==========  ==========  ====================
     97.234 us   36.033 us    1.073 us           3  lib_a
     50.552 us   26.690 us    2.828 us           2  lib_b
     32.010 us   20.847 us    9.684 us           2  lib_c
     43.516 us   43.516 us    7.483 us           1  foo
     46.806 us   46.806 us    3.290 us           1  main

    $ uftrace report -f total,total-max,self-min,total-min,call -s self-min,total-min
    Total time   Total max    Self min   Total min       Calls  Function
    ==========  ==========  ==========  ==========  ==========  ====================
     32.010 us   20.847 us    9.684 us   11.163 us           2  lib_c
     43.516 us   43.516 us    7.483 us   43.516 us           1  foo
     46.806 us   46.806 us    3.290 us   46.806 us           1  main
     50.552 us   26.690 us    2.828 us   23.862 us           2  lib_b
     97.234 us   36.033 us    1.073 us   27.763 us           3  lib_a

각 필드는 아래와 같이 --diff 옵션과 함께 사용될 수 있다.

    $ uftrace report --diff uftrace.data.old -f total,total-min
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record test/t-lib)
    #  [1] diff: uftrace.data.old   (from uftrace record test/t-lib)
    #
     Total time     Total min   Function
    ===========   ===========   ====================
     +34.560 us     +9.884 us   lib_a
     +18.086 us     +8.517 us   lib_b
     +16.887 us    +16.887 us   main
     +15.479 us    +15.479 us   foo
     +10.600 us     +3.127 us   lib_c

    $ uftrace report --diff uftrace.data.old -f total,total-min,self-avg --diff-policy full
    #
    # uftrace diff
    #  [0] base: uftrace.data           (from uftrace record --srcline test/t-lib)
    #  [1] diff: uftrace.data.old	(from uftrace record --srcline test/t-lib)
    #
                      Total time (diff)                      Total min (diff)                       Self avg (diff)   Function
    ===================================   ===================================   ===================================   ====================
     14.616 us   13.796 us    +0.820 us     4.146 us    3.823 us    +0.323 us     0.443 us    0.459 us    -0.016 us   lib_a
      6.529 us    5.957 us    +0.572 us     6.529 us    5.957 us    +0.572 us     0.436 us    0.356 us    +0.080 us   main
      7.700 us    7.173 us    +0.527 us     3.677 us    3.426 us    +0.251 us     0.365 us    0.363 us    +0.002 us   lib_b
      6.093 us    5.601 us    +0.492 us     6.093 us    5.601 us    +0.492 us     0.741 us    0.476 us    +0.265 us   foo
      5.638 us    5.208 us    +0.430 us     2.346 us    2.187 us    +0.159 us     1.646 us    1.510 us    +0.136 us   lib_c

각 필드는 다음과 같은 의미가 있다.

 * total: 함수의 전체 실행 시간
 * total-avg: 각 함수들의 총합 시간의 평균값.
 * total-min: 각 함수들의 총합 시간의 최소값.
 * total-max: 각 함수들의 총합 시간의 최대값.
 * self: 각 함수별 소요 시간.
 * self-avg: 각 함수별 소요 시간의 평균값.
 * self-min: 각 함수별 소요 시간의 최소값.
 * self-max: 각 함수별 소요 시간의 최대값.
 * call: 각 함수들이 호출된 횟수.

기본적으로 설정된 필드값은 'total,self,call'이다.  만약 주어진 필드의 이름이 "+"로
시작된다면, 그 필드는 기본 필드값에 추가될 것이다.  즉, "-f +total-avg" 는
"-f total,self,call,total-avg" 와 같은 것이다.  또한 'none'이라는 특별한 필드도 받을 수
있는데, 이는 필드 출력을 하지 않고 오직 함수 실행 결과만을 보여준다.

TASK FIELDS
======
 * total: 각 작업의 총 소요 시간.
 * self: 각 작업별 소요 시간.
 * func: 작업 내의 함수 갯수.
 * tid: 작업 ID.

기본적으로 설정된 필드값은 'total,self,func,tid'이다.  상세한 설명은 *FIELDS* 를 참고한다.


함께 보기
=========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-tui`(1)


번역자
======
김서영 <gegiraffe@gmail.com>, 강민철 <tegongkang@gmail.com>
