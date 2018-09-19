% UFTRACE(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

NAME
====
uftrace - Function graph tracer for userspace


SYNOPSIS
========
uftrace [*record*|*replay*|*live*|*report*|*info*|*dump*|*recv*|*graph*|*script*|*tui*] [*options*] COMMAND [*command-options*]


DESCRIPTION
===========
The uftrace tool is a function tracer that traces the execution of given
`COMMAND` at the function level.  `COMMAND` should be a C or C++ executable
built with compiler instrumentation (`-pg` or `-finstrument-functions`).
COMMAND needs to have an ELF symbol table (i.e. not be `strip`(1)-ed) in order
for the names of traced functions to be available.

The uftrace command consists of a number of sub-commands, in the manner of
`git`(1) or `perf`(1).  Below is a short description of each sub-command.
For more detailed information, see the respective manual pages.  The options
in this page can be given to any sub-command also.

For convenience, if no sub-command is given, uftrace acts as though the `live`
sub-command was specified, which runs the `record` and `replay` sub-commands in
turn.  See `uftrace-live`(1) for options belonging to the `live` sub-command.
For more detailed analysis, it is better to use `uftrace-record`(1) to save
trace data, and then analyze it with other uftrace commands like
`uftrace-replay`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-dump`(1),
`uftrace-script`(1) or `uftrace-tui`(1).


SUB-COMMANDS
============
record
:   Run a given command and save trace data in a data file or directory.

replay
:   Print recorded function trace data with time durations.

live
:   Do live tracing.  Print function trace of the given command.

report
:   Print various statistics and summary of the recorded trace data.

info
:   Print side-band information like OS version, CPU info, command line and so on.

dump
:   Print raw tracing data in the data files.

recv
:   Save tracing data sent to network

graph
:   Print function call graph

script
:   Run a script for recorded function trace

tui
:   Show text user interface for graph and report


OPTIONS
=======
-?, \--help
:   Print help message and list of options with description

-h, \--help
:   Print help message and list of options with description

\--usage
:   Print usage string

-V, \--version
:   Print program version

-v, \--verbose
:   Print verbose messages.  This option increases a debug level and can be
    used at most 3 times.

\--debug
:   Print debug messages.  This option is same as `-v`/`--verbose` and is
    provided only for backward compatibility.

\--debug-domain=*DOMAIN*[,*DOMAIN*, ...]
:   Limit the printing of debug messages to those belonging to one of the
    DOMAINs specified.  Available domains are: uftrace, symbol, demangle,
    filter, fstack, session, kernel, mcount, dynamic, event, script and dwarf.
    The domains can have an their own debug level optionally (preceded by a
    colon).  For example, `-v --debug-domain=filter:2` will apply debug level
    of 2 to the "filter" domain and apply debug level of 1 to others.

-d *DATA*, \--data=*DATA*
:   Specify name of trace data (directory).  Default is `uftrace.data`.

\--logfile=*FILE*
:   Save warning and debug messages into this file instead of stderr.

\--color=*VAL*
:   Enable or disable color on the output.  Possible values are
    "yes"(= "true" | "1" | "on" ), "no"(= "false" | "0" | "off" ) and "auto".
    The "auto" value is default and turns on coloring if stdout is a terminal.

\--no-pager
:   Do not use a pager.

\--opt-file=*FILE*
:   Read command-line options from the FILE.


SEE ALSO
========
`uftrace-live`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-dump`(1), `uftrace-recv`(1), `uftrace-graph`(1), `uftrace-script`(1), `uftrace-tui(1)`
