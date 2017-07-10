% UFTRACE-RECV(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% May, 2016

NAME
====
uftrace-recv - Receive tracing data from socket and save it to files


SYNOPSIS
========
uftrace recv [*options*]


DESCRIPTION
===========
This command receives tracing data from the network and saves it to files.
Data will be sent using `uftrace-record` with -H/\--host option.

-d *DATA*, \--data=*DATA*
:   Specify directory name to save received data.

\--port=*PORT*
:   Use given port instead of the default (8090).

--run-cmd=*COMMAND*
:   Run given (shell) command as soon as receive data.  For example, one can run "uftrace replay" for received data.


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1)
