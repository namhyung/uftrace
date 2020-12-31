% UFTRACE-LIVE(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

NAME
====
uftrace-live - Trace functions in a command during live execution


SYNOPSIS
========
uftrace [live] [*options*] COMMAND [*command-options*]


DESCRIPTION
===========
This command runs COMMAND and prints its functions with time and thread info.
This is basically the same as running the `uftrace record` and `uftrace replay`
commands in turn, but it does not save a data file.  This command accepts most
options that are accepted by the record or replay commands.


COMMON OPTIONS
==============
-F *FUNC*, \--filter=*FUNC*
:   Set filter to trace selected functions and their children functions.
    This option can be used more than once.  See *FILTERS*.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not to trace selected functions and their children functions.
    This option can be used more than once.  See *FILTERS*.

-H *FUNC*, \--hide=*FUNC*
:   Set filter not to trace selected functions.
    It doesn't affect their subtrees, but hides only the given functions.
    This option can be used more than once.  See *FILTERS*.

-C *FUNC*, \--caller-filter=*FUNC*
:   Set filter to trace callers of selected functions only.
    This option can be used more than once.  See *FILTERS*.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.
    See *TRIGGERS*.

-D *DEPTH*, \--depth=*DEPTH*
:   Set global trace limit in nesting level.  See *FILTERS*.

-t *TIME*, \--time-filter=*TIME*
:   Do not show functions which run under the time threshold.  If some functions
    explicitly have the 'trace' trigger applied, those are always traced
    regardless of execution time.  See *FILTERS*.

\--no-libcall
:   Do not record library function invocations.  Library calls are normally
    traced by hooking calls to the resolver function of dynamic linker in the PLT.
    One can disable it with this option.

\--no-event
:   Disable event recording which is used by default.  Note that explicit event
    tracing by `--event` option is not affected by this.

\--match=*TYPE*
:   Use pattern match using TYPE.  Possible types are `regex` and `glob`.
    Default is `regex`.

\--disable
:   Start uftrace with tracing disabled.  This is only meaningful when used with
    a `trace_on` trigger.


LIVE OPTIONS
============
\--list-event
:   Show available events in the process.

\--report
:   Show live-report before replay.

\--record
:   Do not discard the recorded data.


RECORD OPTIONS
==============
-A *SPEC*, \--argument=*SPEC*
:   Record function arguments.  This option can be used more than once.
    See *ARGUMENTS*.

-R *SPEC*, \--retval=*SPEC*
:   Record function return values.  This option can be used more than once.
    See *ARGUMENTS*.

-P *FUNC*, \--patch=*FUNC*
:   Patch FUNC dynamically.  This is only applicable binaries built by
    gcc with `-pg -mfentry -mnop-mcount` or clang with `-fxray-instrument`.
    This option can be used more than once.  See *DYNAMIC TRACING*.

-U *FUNC*, \--unpatch=*FUNC*
:   Do not apply dynamic patching for FUNC.  This option can be used more than once.
    See *DYNAMIC TRACING*.

-Z *SIZE*, \--size-filter=*SIZE*
:   Patch functions bigger than SIZE bytes dynamically.  See *DYNAMIC TRACING*.

-E *EVENT*, \--event=*EVENT*
:   Enable event tracing.  The event should be available on the system.

-S *SCRIPT_PATH*, \--script=*SCRIPT_PATH*
:   Run a given script to do additional work at the entry and exit of function
    during target program execution.
    The type of script is detected by the postfix such as '.py' for python.
    See *SCRIPT EXECUTION*.

-W, \--watch=*POINT*
:   Add watch point to display POINT if the value is changed.  See *WATCH POINT*.

-a, \--auto-args
:   Automatically record arguments and return values of known functions.
    These are usually functions in standard (C language or system) libraries
    but if debug info is available it includes functions in the user program.

-l, \--nest-libcall
:   Trace function calls between libraries.  By default, uftrace only record
    library call from the main executable.  Implies `--force`.

-k, \--kernel
:   Trace kernel functions as well as user functions.  Only kernel entry/exit
    functions will be traced by default.  Use the `--kernel-depth` option to
    override this.

-K *DEPTH*, \--kernel-depth=*DEPTH*
:   Set kernel max function depth separately.  Implies `--kernel`.

\--signal=*TRG*
:   Set trigger on selected signals rather than functions.  But there are
    restrictions so only a few of trigger actions are support for signals.
    The available actions are: trace_on, trace_off, finish.
    This option can be used more than once.  See *TRIGGERS*.

\--nop
:   Do not record and replay any functions.  This is a no-op and only meaningful
    for performance comparisons.

\--force
:   Allow running uftrace even if some problems occur.  When `uftrace record`
    finds no mcount symbol (which is generated by compiler) in the executable,
    it quits with an error message since uftrace can not trace the program.
    However, it is possible that the user is only interested in functions within
    a dynamically-linked library, in which case this option can be used to cause
    uftrace to run the program regardless.  Also, the `-A`/`--argument` and
    `-R`/`--retval` options work only for binaries built with `-pg`, so uftrace
    will normally exit when it tries to run binaries built without that option.
    This option ignores the warning and goes on tracing without the argument
    and/or return value.

\--time
:   Print running time of children in `time`(1)-style.

-e, \--estimate-return
:   Record only ENTRY data for each function.  This option is useful when the
    target program deals with stack in some way.  Normally uftrace modifies
    task's execution stack frame to hook return from the function.  However
    sometimes it makes troubles and it's hard to handle all the cases properly.
    This option tells uftrace not to hook return address in order to prevent
    those problems.  The return time is estimated as a half of execution time
    of two consecutive functions.


RECORD CONFIG OPTIONS
=====================
-L *PATH*, \--library-path=*PATH*
:   Load necessary internal libraries from this path.  This is mostly for
    testing purposes.

-b *SIZE*, \--buffer=*SIZE*
:   Size of internal buffer in which trace data will be saved.  Default size is
    128k.

\--kernel-buffer=*SIZE*
:   Set kernel tracing buffer size.  The default value (in the kernel) is 1408k.

\--no-pltbind
:   Do not bind dynamic symbol address.  This option uses the `LD_BIND_NOT`
    environment variable to trace library function calls which might be missing
    due to concurrent (first) accesses.  It is not meaningful to use this option
    with the `--no-libcall` option.

\--max-stack=*DEPTH*
:   Set the max function stack depth for tracing.  Default is 1024.

\--num-thread=*NUM*
:   Use NUM threads to record trace data.  Default is 1/4 of online CPUs (but
    when full kernel tracing is enabled, it will use the full number of CPUs).

\--libmcount-single
:   Use single thread version of libmcount for faster recording.  This is
    ignored if the target program links with the pthread library.

\--rt-prio=*PRIO*
:   Boost priority of recording threads to real-time (FIFO) with priority of
    *PRIO*.  This is particularly useful for high-volume data such as full
    kernel tracing.

\--keep-pid
:   Retain same pid for traced program.  For some daemon processes, it is
    important to have same pid when forked.  Running under uftrace normally
    changes pid as it calls fork() again internally.  Note that it might corrupt
    terminal setting so it'd be better using it with `--no-pager` option.

\--no-randomize-addr
:   Disable ASLR (Address Space Layout Randomization).  It makes the target
    process fix its address space layout.


REPLAY OPTIONS
==============
-f *FIELD*, \--output-fields=*FIELD*
:   Customize field in the output.  Possible values are: duration, tid, time,
    delta, elapsed and addr.  Multiple fields can be set by using comma.
    Special field of 'none' can be used (solely) to hide all fields.
    Default is 'duration,tid'.  See *FIELDS*.

\--flat
:   Print flat format rather than C-like format.  This is usually for debugging
    and testing purpose.

\--column-view
:   Show each task in separate column.  This makes easy to distinguish functions
    in different tasks.

\--column-offset=*DEPTH*
:   When `--column-view` option is used, this option specifies the amount of
    offset between each task.  Default is 8.

\--task-newline
:   Interleave a new line when task is changed.  This makes easy to distinguish
    functions in different tasks.

\--no-comment
:   Do not show comments of returned functions.

\--libname
:   Show library name along with function name.


COMMON ANALYSIS OPTIONS
=======================
\--kernel-full
:   Show all kernel functions called outside of user functions.

\--kernel-only
:   Show kernel functions only without user functions.

\--event-full
:   Show all (user) events outside of user functions.

\--demangle=*TYPE*
:   Demangle C++ symbol names.  Possible values are "full", "simple" and "no".
    Default is "simple" which ignores function arguments and template parameters.

-r *RANGE*, \--time-range=*RANGE*
:   Only show functions executed within the time RANGE.  The RANGE can be
    \<start\>~\<stop\> (separated by "~") and one of \<start\> and \<stop\> can
    be omitted.  The \<start\> and \<stop\> are timestamp or elapsed time if
    they have \<time_unit\> postfix, for example '100us'.  However, it is
    highly recommended to use only elapsed time because there is no way to know
    the timestamp before actually running the program.  The timestamp or elapsed
    time can be shown with `-f time` or `-f elapsed` option respectively.


FILTERS
=======
The uftrace tool supports filtering out uninteresting functions.  Filtering is
highly recommended since it helps users focus on the interesting functions and
reduces the data size.  When uftrace is called it receives two types of function
filter; an opt-in filter with `-F`/`--filter` and an opt-out filter with
`-N`/`--notrace`.  These filters can be applied either at record time or
replay time.

The first one is an opt-in filter. By default, it doesn't trace anything.  But
when one of the specified functions is executed, tracing is started.  When the
function returns, tracing is stopped again.

For example, consider a simple program which calls `a()`, `b()` and `c()` in turn.

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

Normally uftrace will trace all the functions from `main()` to `c()`.

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

In the above example, the command name `live` is explicitly used, but it can be
omitted because uftrace uses `live` command by default.  So the above command
can be reused as `uftrace ./abc` in short.

But when the `-F b` filter option is used, it will not trace `main()` or `a()`
but only `b()` and `c()`.

    $ uftrace -F b ./abc
    # DURATION    TID     FUNCTION
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

The second type of filter is opt-out. By default, everything is traced, but when
one of the specified functions is executed, tracing stops.  When the excluded
function returns, tracing is started again.

In the above example, you can omit the function `b()` and all calls it makes
with the `-N` option.

    $ uftrace -N b ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

You can hide the function `b()` only without affecting the calls it makes in its
subtree functions with `-H` option.

    $ uftrace -H b ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       3.880 us [ 1234] |     c();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

The above `-H` option is especially useful when hiding std namespace functions
in C++ programs by using `-H ^std::` option setting.

If users only care about specific functions and want to know how they are called,
one can use the caller filter.  It makes the function as leaf and records the
parent functions to the function.

    $ uftrace -C b ./abc
    # DURATION    TID     FUNCTION
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

In the above example, functions not in the calling path were not shown.  Also
the function 'c' - which is a child of the function 'b' - is also hidden.

In addition, you can limit the nesting level of functions with the `-D` option.

    $ uftrace -D 3 ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

In the above example, uftrace only prints functions up to a depth of 3, so
leaf function `c()` was omitted.  Note that the `-D` option works with `-F`.

Sometimes it's useful to see long-running functions only.  This is good because
there are usually many tiny functions that are not interesting.
The `-t`/`--time-filter` option implements the time-based filter that only
records functions which run longer than the given threshold.  In the above
example, the user might want to see functions running more than
5 micro-seconds like below:

    $ uftrace -t 5us ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

You can also set triggers on filtered functions.  See *TRIGGERS* section below
for details.

When kernel function tracing is enabled, you can also set the filters on kernel
functions by marking the symbol with the `@kernel` modifier.  The following
example will show all user functions and the (kernel) page fault handler.

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
The uftrace tool supports triggering actions on selected function calls (with or
without filters) and/or signals.  Currently supported triggers are listed below.
The BNF for trigger specification is as follows:

    <trigger>    :=  <symbol> "@" <actions>
    <actions>    :=  <action>  | <action> "," <actions>
    <action>     :=  "depth="<num> | "backtrace" | "trace" | "trace_on" | "trace_off" |
                     "recover" | "color="<color> | "time="<time_spec> | "read="<read_spec> |
                     "finish" | "filter" | "notrace" | "hide"
    <time_spec>  :=  <num> [ <time_unit> ]
    <time_unit>  :=  "ns" | "nsec" | "us" | "usec" | "ms" | "msec" | "s" | "sec" | "m" | "min"
    <read_spec>  :=  "proc/statm" | "page-fault" | "pmu-cycle" | "pmu-cache" | "pmu-branch"

The `depth` trigger is to change filter depth during execution of the function.
It can be used to apply different filter depths for different functions.  And
the `backtrace` trigger is used to print a stack backtrace at replay time.

The color trigger is to change the color of the function in replay output.
The supported colors are `red`, `green`, `blue`, `yellow`, `magenta`, `cyan`,
`bold`, and `gray`.

The following example shows how triggers work.  The global filter maximum depth
is 5, but when function `b()` is called, it is changed to 1, so functions below
`b()` will not shown.

    $ uftrace -D 5 -T 'b@depth=1' ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

The `backtrace` trigger is only meaningful in the replay command.

The `trace_on` and `trace_off` actions (the `_` can be omitted as `traceon`
and `traceoff`) control whether uftrace records the specified functions or not.

The `recover` trigger is for some corner cases in which the process accesses the
callstack directly.  During tracing of the v8 javascript engine, for example, it
kept getting segfaults in the garbage collection stage.  It was because v8
incorporates the return address into compiled code objects(?).  The `recover`
trigger restores the original return address at the function entry point and
resets to the uftrace return hook address again at function exit.  I was managed
to work around the segfault by setting the `recover` trigger on the related
function (specifically `ExitFrame::Iterate`).

The `time` trigger is to change time filter setting during execution of the
function.  It can be used to apply different time filter for different functions.

The `read` trigger is to read some information at runtime.  The result will be
recorded as (builtin) events at the beginning and the end of a given function.
As of now, following events are supported:

 * "proc/statm": process memory stat from /proc filesystem
 * "page-fault": number of page faults using getrusage(2)
 * "pmu-cycle":  cpu cycles and instructions using Linux perf-event syscall
 * "pmu-cache":  (cpu) cache-references and misses using Linux perf-event syscall
 * "pmu-branch": branch instructions and misses using Linux perf-event syscall

The results are printed as events (comments) like below.

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

The `finish` trigger is to end recording.  The process still can run and this
can be useful to trace unterminated processes like daemon.

The `filter` and `notrace` triggers have same effect as `-F`/`--filter` and
`-N`/`--notrace` options respectively.

The `hide` trigger has the same effect as `-H`/`--hide` option that hides the
given functions, but do not affect to the functions in their subtree unlike
the `notrace` trigger.

Triggers only work for user-level functions for now.

The trigger can be used for signals as well.  This is done by signal trigger
with \--signal option.  The syntax is similar to function trigger but only
"trace_on", "trace_off" and "finish" trigger actions are supported.

    $ uftrace --signal 'SIGUSR1@finish' ./some-daemon


ARGUMENTS
=========
The uftrace tool supports recording function arguments and/or return values
using the -A/\--argument and -R/\--retval options respectively.
The syntax is very similar to that of triggers:

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

The -A/\--argument option takes a symbol name pattern and its optional specs.
The spec is started by argN where N is an index of the arguments.  The index
starts from 1 and corresponds to the argument passing order of the calling
convention on the system.  Note that the indexes of arguments are separately
counted for integer (or pointer) and floating-point type, and they can interfere
depending on the calling convention.  The argN is for integer arguments and
fpargN is for floating-point arguments.

Users can optionally specify a format and size for the arguments and/or return
values.  The "d" format or without format field, uftrace treats them as
'long int' type for integers and 'double' for floating-point numbers.
The "i" format makes it signed integer type and "u" format is for unsigned
type.  Both are printed as decimal while "x" format makes it printed as
hexadecimal.  The "s" format is for null-terminated string type and "c" format
is for character type.  The "f" format is for floating-point type and is
meaningful only for return value (generally).  Note that fpargN doesn't take
the format field since it's always floating-point.  The "S" format is for
std::string, but it only supports libstdc++ library as of yet.  Finally,
the "p" format is for function pointer. Once the target address is recorded,
it will be displayed as function name.

Please beware when using string type arguments since it can crash the program
if the (pointer) value is invalid.  Actually uftrace tries to keep track of
valid ranges of process address space but it might miss some corner cases.

It is also possible to specify a certain register name or stack offset for
arguments (but not for return value).  The following register names can be used
for argument:

 * x86: rdi, rsi, rdx, rcx, r8, r9 (for integer), xmm[0-7] (for floating-point)
 * arm: r[0-3] (for integer), s[0-15] or d[0-7] (for floating-point)

Examples are below:

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

Note that these arguments and return value are recorded only if the executable
was built with the `-pg` option.  Executables built with `-finstrument-functions`
will ignore it except for library calls.  Recording of arguments and return
values only works with user-level functions for now.

If the target program is built with debug info like DWARF, uftrace can identify
number of arguments and their types automatically (when built with libdw).
Also arguments and return value of some well-known library functions are
provided even if the debug info is not available.  In these cases user don't
need to specify spec of the arguments and return value manually - just a
function name (or pattern) is enough.  In fact, manual argspec will suppress
the automatic argspec.

For example, the above example can be written like below:

    $ uftrace -A . -R main -F main ./hello
    Hello world
    # DURATION     TID     FUNCTION
                [ 18948] | main(1, 0x7ffeeb7590b8) {
       7.183 us [ 18948] |   puts("Hello world");
       9.832 us [ 18948] | } = 0; /* main */

Note that argument pattern (".") matches to any character so it recorded
all (supported) functions.  It shows two arguments for "main" and a single
string argument for "puts".  If you simply want to see all arguments and
return values of every functions (if supported), use -a/\--auto-args option.


FIELDS
======
The uftrace allows for user to customize the replay output with a couple of
fields.  Here the field means info on the left side of the pipe (|) character.
By default it uses duration and tid fields, but you can use other fields in any
order like:

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

Each field has following meaning:

 * tid: task id (obtained by gettid(2))
 * duration: function execution time
 * time: timestamp at the execution
 * delta: difference between two timestamp in a task
 * elapsed: elapsed time from the first timestamp
 * addr: address of the function
 * task: task name (comm)
 * module: library or executable name of the function

The default value is 'duration,tid'.  If given field name starts with "+", then
it'll be appended to the default fields.  So "-f +time" is as same as
"-f duration,tid,time".  And it also accepts a special field name of 'none'
which disables the field display and shows function output only.


DYNAMIC TRACING
===============
The uftrace tool supports dynamic function tracing which can be enabled at
runtime (load-time, to be precise) on x86_64.  Before recording functions,
normally you need to build the target program with `-pg` (or
`-finstrument-functions`), then it has some performance impact because all
funtions call `mcount()`.

With dynamic tracing, you can trace specific functions only given by the
`-P`/`--patch` option and can also disable specific functions given by the
`-U`/`--unpatch` option.  With capstone disassembly engine you even don't need
to (re)compile the target with the option above.  Now uftrace can analyze the
instructions and (if possible) it can copy them to a different place and rewrite
it to call `mcount()` function) so that it can be traced by uftrace.  After that
the control is passed to the copied instructions and then returned back to the
remaining instructions.

If the capstone is not available, you need to add some more compiler (gcc)
options when building the target program.  The gcc 5.1 or more recent versions
provide `-mfentry` and `-mnop-mcount` options which add instrumentation code
(i.e.  calling `mcount()` function) at the very beginning of a function and
convert the instruction to a NOP.  Then it has almost zero performance overhead
when running in a normal condition.  The uftrace can selectively convert it 
back to call `mcount()` using `-P` option.

The following example shows an error message when normally running uftrace.
Because the binary doesn't call any instrumentation code (i.e. 'mcount').

    $ gcc -o abc -pg -mfentry -mnop-mcount tests/s-abc.c
    $ uftrace abc
    uftrace: /home/namhyung/project/uftrace/cmd-record.c:1305:check_binary
      ERROR: Can't find 'mcount' symbol in the 'abc'.
             It seems not to be compiled with -pg or -finstrument-functions flag
             which generates traceable code.  Please check your binary file.

But when the `-P a` patch option is used, and then only it can dynamically
trace `a()`.

    $ uftrace --no-libcall -P a abc
    # DURATION    TID     FUNCTION
       0.923 us [19379] | a();

In addition, you can enable all functions using '.' (for glob, '*') that
matches to any character in a regex pattern with `P` option.

    $ uftrace --no-libcall -P . abc
    # DURATION    TID     FUNCTION
                [19387] | main() {
                [19387] |   a() {
                [19387] |     b() {
       0.940 us [19387] |       c();
       2.030 us [19387] |     } /* b */
       2.451 us [19387] |   } /* a */
       3.289 us [19387] | } /* main */

Note that `-U` option has the opposite effect of `-P` option so users can
the both to fine-control.  The option comes later will override the formers.
For example if you want to trace all functions but 'a' in the above:

    $ uftrace --no-libcall -P . -U a  abc
    # DURATION    TID     FUNCTION
                [19390] | main() {
                [19390] |   b() {
       0.983 us [19390] |     c();
       2.012 us [19390] |   } /* b */
       3.373 us [19390] | } /* main */

The order of the options is important, if you change it like `-U a -P .` then
it will trace all the functions since `-P .` will be effective for all.

In addition, the `-U` option can be used to disable functions in binaries
built with `-pg` (and `-mfentry` or `-mrecord-mcount`).  It might require
capstone to parse the instructions.

Clang/LLVM 4.0 provides a dynamic instrumentation technique called
[X-ray](http://llvm.org/docs/XRay.html).  It's similar to a combination of
`gcc -mfentry -mnop-mcount` and `-finstrument-functions`.  The uftrace also
supports dynamic tracing on the executables built with the `X-ray`.

For example, you can build the target program by clang with the below option
and equally use `-P` option for dynamic tracing like below:

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


SCRIPT EXECUTION
================
The uftrace tool supports script execution for each function entry and exit.
The supported script types are Python 2.7, Python 3 and Lua 5.1 as of now.

The user can write four functions. 'uftrace_entry' and 'uftrace_exit' are
executed whenever each function is executed at the entry and exit.  However
'uftrace_begin' and 'uftrace_end' are only executed once when the target program
begins and ends.

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

The above script can be executed in record time as follows:

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

The 'ctx' variable is a dictionary type that contains the below information.

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

Each field in 'script_context' can be read inside the script.
Please see `uftrace-script`(1) for details about scripting.


WATCH POINT
===========
The uftrace watch point is to display certain value only if it's changed.
It's conceptually same as debugger's but only works at function entry and exit
so it might miss some updates.

As of now, following watch points are supported:

 * "cpu" : cpu number current task is running on

Like read triggers, the result is displayed as event (comment):

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


SEE ALSO
========
`uftrace-record`(1), `uftrace-replay`(1), `uftrace-report`(1), `uftrace-script`(1)
