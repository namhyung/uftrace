% UFTRACE-SCRIPT(1) Uftrace User Manuals
% Honggyu Kim <honggyu.kp@gmail.com>
% July, 2017

NAME
====
uftrace-script - Run a script for recorded function trace


SYNOPSIS
========
uftrace script [*options*]


DESCRIPTION
===========
This command runs a script for trace data recorded using the `uftrace-record`(1) command.


OPTIONS
=======
-F *FUNC*, \--filter=*FUNC*
:   Set filter to trace selected functions only.  This option can be used more than once.  See 'uftrace-replay' for details.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not to trace selected functions (or the functions called underneath them).  This option can be used more than once.  See 'uftrace-replay' for details.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.  See 'uftrace-replay' for details.

-t *TIME*, \--time-filter=*TIME*
:   Do not show functions which run under the time threshold.  If some functions explicitly have the 'trace' trigger applied, those are always traced regardless of execution time.

\--tid=*TID*[,*TID*,...]
:   Only print functions called by the given threads.  To see the list of threads in the data file, you can use `uftrace report --threads` or `uftrace info`.  This option can also be used more than once.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

-r *RANGE*, \--time-range=*RANGE*
:   Only show functions executed within the time RANGE.  The RANGE can be \<start\>~\<stop\> (separated by "~") and one of \<start\> and \<stop\> can be omitted.  The \<start\> and \<stop\> are timestamp or elapsed time if they have \<time_unit\> postfix, for example '100us'.  The timestamp or elapsed time can be shown with `-f time` or `-f elapsed` option respectively.

-S *SCRIPT_PATH*, \--script=*SCRIPT_PATH*
:   Add a script to do addtional work at the entry and exit of function.  The type of script is detected by the postfix such as '.py' for python.

\--record COMMAND [*command-options*]
:   Record a new trace before running a given script.

--match=*TYPE*
:   Use pattern match using TYPE.  Possible types are `regex` and `glob`.  Default is `regex`.


EXAMPLES
========
The uftrace tool supports script execution for each function entry and exit.  The supported script is only Python 2.7 as of now.

The user can write four functions. 'uftrace_entry' and 'uftrace_exit' are executed whenever each function is executed at the entry and exit.  However 'uftrace_begin' and 'uftrace_end' are only executed once when the target program begins and ends.

    $ cat scripts/simple.py
    def uftrace_begin():
        print("program begins...")

    def uftrace_entry(ctx):
        func = ctx["name"]
        print("entry : " + func + "()")

    def uftrace_exit(ctx):
        func = ctx["name"]
        print("exit  : " + func + "()")

    def uftrace_end():
        print("program is finished")

The 'ctx' variable is a dictionary type that contains the below information.

    /* context information passed to script */
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

The above script can be executed while reading the recorded data.  The usage is as follows:

    $ uftrace record -F main tests/t-abc

    $ uftrace script -S scripts/simple.py
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

The below is another example that shows the different output compared to previous one for the same recorded data.  The output looks similar to 'uftrace replay' this time.

    $ uftrace script -S scripts/replay.py
    # DURATION    TID     FUNCTION
                [25794] | main() {
                [25794] |   a() {
                [25794] |     b() {
                [25794] |       c() {
                [25794] |         getpid() {
      11.037 us [25794] |         } /* getpid */
      44.752 us [25794] |       } /* c */
      70.924 us [25794] |     } /* b */
      98.191 us [25794] |   } /* a */
     124.329 us [25794] | } /* main */

The python script above can be modified to do more output customization.

The python script can have an optional "UFTRACE_FUNCS" list which can have name (or pattern depending on the --match option) of functions to run the script.  If it exists, only matched functions will run the script.  For example, if you add following lines to the script, it will run only for functions with a single letter name.

    $ echo 'UFTRACE_FUNCS = [ "^.$" ]' >> replay.py
    $ uftrace script -S replay.py
    # DURATION    TID     FUNCTION
                [25794] |   a() {
                [25794] |     b() {
                [25794] |       c() {
      44.752 us [25794] |       } /* c */
      70.924 us [25794] |     } /* b */
      98.191 us [25794] |   } /* a */

Also script can have options for record if it requires some form of data (i.e. function argument or return value).  A comment line started with "uftrace-option:" will provide (a part of) such options when recording.

    $ cat arg.py
    #
    # uftrace-option: -A a@arg1 -R b@retval
    #
    def uftrace_entry(ctx):
        if "args" in ctx:
            print(ctx["name"] + " has args")
    def uftrace_exit(ctx):
        if "retval" in ctx:
            print(ctx["name"] + " has retval")

    $ uftrace record -S arg.py abc
    a has args
    b has retval
    $ uftrace script -S arg.py
    a has args
    b has retval


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-live`(1)
