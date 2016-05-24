QUICK GUIDE
===========

To build uftrace, you need to install basic software development tools first -
like gcc and make.  And also you need to install dependent softwares, please
see DEPENDENCY section for details.

Once you installed required software(s), you can run `make' to build it.

    $ make

It builds uftrace and resulting binary exists in the current directory.
This is good for testing, but you'll want to install it for normal use.

    $ sudo make install

It installs the uftrace under /usr/local by default, if you want install it
to other location, you can set prefix variable when invoking make.
More fine-tuning can be done by optional configure stage (see below).

    $ make prefix=/usr
    $ sudo make install

The output of build looks like linux kernel style, users can see original
build command lines with V=1 (like kernel).

    $ make V=1


CONFIGURATION
=============

It implements own version of configure script to save user preferences.
The config file (named ".config") is created if not exist on build time.
User can set custom installation directories or build directory.

    $ ./configure --help
    Usage: ./configure [<options>]

      --help             print this message
      --prefix=<DIR>     set install root dir as <DIR>        (default: /usr/local)
      --bindir=<DIR>     set executable install dir as <DIR>  (default: ${prefix}/bin)
      --libdir=<DIR>     set library install dir as <DIR>     (default: ${prefix}/lib)
      --mandir=<DIR>     set manual doc install dir as <DIR>  (default: ${prefix}/share/man)
      --objdir=<DIR>     set build dir as <DIR>               (default: ${PWD})

The 'make config' command has same effect.


DEPENDENCY
==========

Currently uftrace depends on libelf from elfutils project for ELF symbol
manipulation.  You need to install it first in order to build uftrace.

On debian based systems (like Ubuntu), libelf-dev package will provide
required libraries/files.

    $ sudo apt-get install libelf-dev

On redhat based systems (like Fedora, RHEL), it'll be elfutils-libelf-devel.

    $ sudo yum install elfutils-libelf-devel

It also uses libstdc++ library to demangle C++ symbols in full detail.
But it's not mandatory as uftrace has its own demangler for shorter symbol
name (it omits arguments, templates and so on).
