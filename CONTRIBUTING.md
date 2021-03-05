Contributing to uftrace
=======================

Thanks for considering contribution to uftrace.  You can git clone the
uftrace source on the following address and send PR with your patch.  But,
before doing that, I recommend you to read this to follow the conventions.

  https://github.com/namhyung/uftrace


Coding style
------------
The uftrace is written in C and mostly follows the coding style of the
Linux kernel [1].  The only different is where to put the closing brace
and start of subsequent block.  I prefer to put it at a separate line for
readability.  For example:

    if (cond == A) {
    	do_some_thing();
    }
    else if (cond == B) {
    	do_other_thing();
    }

Please note that the position of the "else if" line.

For python programs (for tests or scripts), use 4 spaces to indent.

[1] https://www.kernel.org/doc/Documentation/process/coding-style.rst 


Include subject word in message header
--------------------------------------

Although uftrace has a small codebase, I believe it's a good convention
to prefix your subject line with colon.  This lets me and other
developers more easily distinguish patches from other subject.

    $ git log --oneline --graph
    *   fef4226 Merge branch 'misc-fix'
    |\  
    | * 54a4ef0 test: Fix to be able to call runtest.py directly
    | * 6bbe4a0 graph: Skip kernel functions outside of user
    | * a76c7cb kernel: Use real address for filter match
    |/  
    ...


Signing your patch
------------------

The sign-off is a simple line at the end of the explanation for the
patch, which certifies that you wrote it or otherwise have the right to
pass it on as an open-source patch.  The rules are pretty simple: if you
can certify the below:

        Developer's Certificate of Origin 1.1

        By making a contribution to this project, I certify that:

        (a) The contribution was created in whole or in part by me and I
            have the right to submit it under the open source license
            indicated in the file; or

        (b) The contribution is based upon previous work that, to the best
            of my knowledge, is covered under an appropriate open source
            license and I have the right under that license to submit that
            work with modifications, whether created in whole or in part
            by me, under the same open source license (unless I am
            permitted to submit under a different license), as indicated
            in the file; or

        (c) The contribution was provided directly to me by some other
            person who certified (a), (b) or (c) and I have not modified
            it.

        (d) I understand and agree that this project and the contribution
            are public and that a record of the contribution (including all
            personal information I submit with it, including my sign-off) is
            maintained indefinitely and may be redistributed consistent with
            this project or the open source license(s) involved.

then you just add a line saying

	Signed-off-by: Random J Developer <random@developer.example.org>

using your real name (sorry, no pseudonyms or anonymous contributions.)
