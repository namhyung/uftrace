# uftrace-test

This document describes the test facilities provided by uftrace.



## NAME

`uftrace/tests/runtest.py` - Tests various test cases in the `uftrace/tests`



## SYNOPSIS

./runtest.py  [*case*]  \[*option*]



## DESCRIPTION

This program supports multiple tests and can be found through the options below.



## OPTIONS

[case]  : If nothing is entered, the test progresses for the entire test case. 

​              Test number, test case name (partial): Test progress for the test case

-h, --help  : show this help message and exit

-f FLAGS, --profile-flags FLAGS : comma separated list of compiler profiling flags.  

-O OPTS, --optimize-levels OPTS : compiler optimization levels

-p, --profile-pg : profiling with -pg option

-i, --instrument-functions : profiling with -finstrument-functions option

-d, --diff  : show diff result if not matched. The comparison result of uftrace execution is stored in ` t[testnumber]_testname.py`

-v, --verbose : show internal command and result for debugging (Up to 3 additional)

-n, --no-color : suppress color in the output

-t TIMEOUT, --timeout TIMEOUT : fail test if it runs more than TIMEOUT seconds



## EXAMPEL

This command shows information like the following:

````
root@ubuntu:~/uftrace/tests# ./runtest.py 001
Test case                 pg             finstrument-fu
------------------------: O0 O1 O2 O3 Os O0 O1 O2 O3 Os
001 basic               : OK OK OK OK OK OK OK OK OK OK

runtime test stats
====================
total    10  Tests executed (success: 100.00%)
  OK:    10  Test succeeded
  OK:     0  Test succeeded (with some fixup)
  NG:     0  Different test result
  NZ:     0  Non-zero return value
  SG:     0  Abnormal exit by signal
  TM:     0  Test ran too long
  BI:     0  Build failed
  LA:     0  Unsupported Language
  SK:     0  Skipped
````

You can use the -v option to view test internal information :

````
root@ubuntu:~/uftrace/tests# ./runtest.py 001 -v -O1
Test case                 pg fi
------------------------: O1 O1
build command: gcc -o t-abc -fno-inline -fno-builtin -fno-ipa-cp -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0  -pg -O1  s-abc.c   
test command: ../uftrace --no-pager --no-event -L.. t-abc
=========== original ===========
# DURATION     TID     FUNCTION
   0.725 us [  4459] | __monstartup();
   0.275 us [  4459] | __cxa_atexit();
            [  4459] | main() {
            [  4459] |   a() {
            [  4459] |     b() {
            [  4459] |       c() {
   0.294 us [  4459] |         getpid();
   0.612 us [  4459] |       } /* c */
   0.796 us [  4459] |     } /* b */
   0.961 us [  4459] |   } /* a */
   1.134 us [  4459] | } /* main */

===========  result  ===========
main() {
   a() {
     b() {
       c() {
         getpid();
       } /* c */
     } /* b */
   } /* a */
 } /* main */
=========== expected ===========
main() {
   a() {
     b() {
       c() {
         getpid();
       } /* c */
     } /* b */
   } /* a */
 } /* main */
build command: gcc -o t-abc -fno-inline -fno-builtin -fno-ipa-cp -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0  -finstrument-functions -O1  s-abc.c   
test command: ../uftrace --no-pager --no-event -L.. t-abc
=========== original ===========
# DURATION     TID     FUNCTION
            [  4468] | main() {
            [  4468] |   a() {
            [  4468] |     b() {
            [  4468] |       c() {
   0.623 us [  4468] |         getpid();
   1.925 us [  4468] |       } /* c */
   2.124 us [  4468] |     } /* b */
   2.495 us [  4468] |   } /* a */
   2.880 us [  4468] | } /* main */

===========  result  ===========
main() {
   a() {
     b() {
       c() {
         getpid();
       } /* c */
     } /* b */
   } /* a */
 } /* main */
=========== expected ===========
main() {
   a() {
     b() {
       c() {
         getpid();
       } /* c */
     } /* b */
   } /* a */
 } /* main */
001 basic               : OK OK

runtime test stats
====================
total     2  Tests executed (success: 100.00%)
  OK:     2  Test succeeded
  OK:     0  Test succeeded (with some fixup)
  NG:     0  Different test result
  NZ:     0  Non-zero return value
  SG:     0  Abnormal exit by signal
  TM:     0  Test ran too long
  BI:     0  Build failed
  LA:     0  Unsupported Language
  SK:     0  Skipped
````



If you have the compiler profiling flags you want, you can use -f as an argument. Frequently used pg and instrument-functions options are predefined. Use the -v option to check for arguments in the bulid command line.

program instrumentation option reference :  https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html

````
root@ubuntu:~/uftrace/tests# ./runtest.py 001 -f fprofile-arcs -v -O1
Test case                 fp
------------------------: O1
build command: gcc -o t-abc -fno-inline -fno-builtin -fno-ipa-cp -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0  -fprofile-arcs -O1  s-abc.c   
test command: ../uftrace --no-pager --no-event -L.. t-abc

````

``````
root@ubuntu:~/uftrace/tests# ./runtest.py 001 -v -O1
Test case                 pg fi
------------------------: O1 O1
build command: gcc -o t-abc -fno-inline -fno-builtin -fno-ipa-cp -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0  -pg -O1  s-abc.c   
test command: ../uftrace --no-pager --no-event -L.. t-abc
``````

`````
root@ubuntu:~/uftrace/tests# ./runtest.py 001 -i -v -O1
Test case                 fi
------------------------: O1
build command: gcc -o t-abc -fno-inline -fno-builtin -fno-ipa-cp -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0  -finstrument-functions -O1  s-abc.c   
test command: ../uftrace --no-pager --no-event -L.. t-abc
`````

`````
root@ubuntu:~/uftrace/tests# ./runtest.py 001 -p -v -O1
Test case                 pg
------------------------: O1
build command: gcc -o t-abc -fno-inline -fno-builtin -fno-ipa-cp -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0  -pg -O1  s-abc.c   
test command: ../uftrace --no-pager --no-event -L.. t-abc

`````