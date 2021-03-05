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
-s *KEYS*[,*KEYS*,...], \--sort=*KEYS*[,*KEYS*,...]
:   주어진 키를 이용해 함수들을 분류한다. 다수의 키들은 쉼표(,)로 분리할 수 있고,
    가능한 키들에는 `total` (time), `self` (time), `call`, `func`, `avg`, `min`,
    `max`가 있다. 처음 세개의 키는 `--avg-total` 와 `--avg-self` 옵션이 주어지지
    않은 경우에만 사용할 수 있다. 이러한 옵션 중 하나를 사용하는 경우에는 마지막
    세개의 키와 함께 이용해야한다.

\--avg-total
:   각 함수의 총 시간(total time)의 평균, 최소, 최대 시간을 보여준다.

\--avg-self
:   각 함수의 자체 시간(self time)의 평균, 최소, 최대 시간을 보여준다.

\--task
:   함수의 통계자료가 아닌 태스크를 요약해서 보고한다.

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


함께 보기
=========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-tui`(1)


번역자
======
김서영 <gegiraffe@gmail.com>
