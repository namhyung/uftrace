Contributing to uftrace
=======================

Thanks for considering contribution to uftrace.  You can git clone the
uftrace source on the following address and send PR with your patch.  But,
before doing that, I recommend you to read this to follow the conventions.

  https://github.com/namhyung/uftrace


Coding style
------------
The uftrace is written in C and mostly follows
[Linux kernel coding style](https://www.kernel.org/doc/Documentation/process/coding-style.rst)
with a few differences.

The uftrace repository provides a way to automatically apply formatting
with the help of [pre-commit](https://pre-commit.com) and
[clang-format](https://clang.llvm.org/docs/ClangFormat.html) so that
our source code has a consistent coding style at all times.

You need to install pre-commit package but please note that python version 3.7
or higher is required.  The installation can be done as follows.

    $ python3 -m pip install pre-commit

Then you can simply install a pre-commit hook inside the uftrace source
directory as follows.

    $ pre-commit install
    pre-commit installed at .git/hooks/pre-commit

After pre-commit installation, coding style check is done automatically
whenever you try to create a commit as follows.

    $ git commit -s
        ...
    clang-format.............................................................Failed
    - hook id: clang-format
    - files were modified by this hook

If your change doesn't follow the coding style, then clang-format check
fails and also modifies your code to follow the pre-configured uftrace
coding style, which is written at [.clang-format](.clang-format).

If the code is modified by clang-format, then please run `git add -u`
and create a commit again to include the changes made by clang-format.

You can also run coding style check by running pre-commit manually as
follows.

    $ git add -u
    $ pre-commit run

It will check the coding style only for the changes in the git staging
area and automatically reformatted if the check fails.


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
