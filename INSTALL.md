QUICK GUIDE
===========

On Linux distros, following commands will build and install uftrace from source.

    $ sudo misc/install-deps.sh    # optional for advanced features
    $ ./configure                  # --prefix can be used to change install dir
    $ make
    $ sudo make install

For more information, please see below.


GETTING THE SOURCE
==================
The latest version of uftrace is available at Github.

  https://github.com/namhyung/uftrace


DEPENDENCY
==========

The uftrace is written in C and tried to minimize external dependencies.
Currently, uftrace can be built without any external libraries.  But in order to
use more advanced features, it'd be better to install them like below.

Firstly, please make sure `pkg-config` is installed in the system to properly
detect the dependencies of uftrace.  Otherwise, some packages may not be
detected even if they are already installed and it disables some features of
uftrace.

Historically uftrace depended on the `libelf` from elfutils project for ELF
file manipulation.  While it's not mandatory anymore, we recommend you to
install it for better handling of ELF binaries.  Also `libdw` library is
recommended to be installed in order to process DWARF debug information.  The
libdw itself depends on the `libelf`, so you can just install `libdw`.

On debian based systems (like Ubuntu), `libdw-dev` package will provide
required libraries/files.

    $ sudo apt-get install libdw-dev

On redhat based systems (like Fedora, RHEL), it'll be `elfutils-devel`.

    $ sudo dnf install elfutils-devel

It also uses libstdc++ library to demangle C++ symbols in full detail.
But it's not mandatory as uftrace has its own demangler for shorter symbol
name (it omits arguments, templates and so on).

And ncursesw library is to implement text user interface (TUI) on console.
The ncurses(w) library provides terminal handling routines so `uftrace tui`
command is built on top of them.  As it improves user experience of trace data
analysis, you need to consider install it if you do things like `uftrace graph`
or `uftrace report` frequently.

Also it needs `pandoc` to build man pages from the markdown document.


BUILD
=====

To build uftrace, you need to install basic software development tools first -
like gcc and make.  And also you need to install dependent softwares, please
see DEPENDENCY section for details.

Once you installed required software(s), you can run `make` to build it.

    $ make

It builds uftrace and resulting binary exists in the current directory.
This is good for testing, but you'll want to install it for normal use.

    $ sudo make install

It installs the uftrace under /usr/local by default, if you want install it
to other location, you can set the `prefix` variable when invoking the
configure before running make. (see below).

    $ ./configure --prefix=/usr
    $ make
    $ sudo make install

The output of build looks like linux kernel style, users can see original
build command lines with V=1 (like kernel).

    $ make V=1


CONFIGURATION
=============

The uftrace implements own version of configure script to save user
preferences.  The config file (named `.config`) is created if not exist
on build time with default options.  User can set custom installation
directories or build directory with this script.

    $ ./configure --help
    Usage: ./configure [<options>]

      --help                print this message
      --prefix=<DIR>        set install root dir as <DIR>        (default: /usr/local)
      --bindir=<DIR>        set executable install dir as <DIR>  (default: ${prefix}/bin)
      --libdir=<DIR>        set library install dir as <DIR>     (default: ${prefix}/lib)
      --mandir=<DIR>        set manual doc install dir as <DIR>  (default: ${prefix}/share/man)
      --objdir=<DIR>        set build dir as <DIR>               (default: ${PWD})
      --sysconfdir=<DIR>    override the etc dir as <DIR>

      --with-elfutils=<DIR> search for elfutils in <DIR>/include and <DIR>/lib

      --without-libelf      build without libelf (and libdw)     (even if found on the system)
      --without-libdw       build without libdw                  (even if found on the system)
      --without-libstdc++   build without libstdc++              (even if found on the system)
      --without-libpython   build without libpython              (even if found on the system)
      --without-libluajit   build without libluajit              (even if found on the system)
      --without-libncurses  build without libncursesw            (even if found on the system)
      --without-capstone    build without libcapstone            (even if found on the system)
      --without-perf        build without perf event             (even if available)
      --without-schedule    build without scheduler event        (even if available)

      --arch=<ARCH>         set target architecture              (default: system default arch)
                            e.g. x86_64, aarch64, i386, or arm
      --cross-compile=<CROSS_COMPILE>
                            Specify the compiler prefix during compilation
                            e.g. CC is overridden by $(CROSS_COMPILE)gcc
      --cflags=<CFLAGS>     pass extra C compiler flags
      --ldflags=<LDFLAGS>   pass extra linker flags

      -p                    preserve old setting

      Some influential environment variables:
        ARCH                Target architecture    e.g. x86_64, aarch64, i386, or arm
        CROSS_COMPILE       Specify the compiler prefix during compilation
                            e.g. CC is overridden by $(CROSS_COMPILE)gcc
        CFLAGS              C compiler flags
        LDFLAGS             linker flags

Also you can set the target architecture and compiler options like CC, CFLAGS.

It's also possible to disable some features depending on external libraries or
system behaviors.  For example --without-libpython option will make scripting
feature disabled - `uftrace script` command will still exist but won't work.

For cross compile, you may want to setup the toolchain something like below:

    $ export CROSS_COMPILE=/path/to/cross/toolchain/arm-unknown-linux-gnueabihf-
    $ ARCH=arm CFLAGS='--sysroot /path/to/sysroot' ./configure
        or
    $ ./configure --arch=arm --cflags='--sysroot /path/to/sysroot' \
          --cross-compile=/path/to/cross/toolchain/arm-unknown-linux-gnueabihf-

This assumes you already installed the cross-built `libelf` on the sysroot
directory.  Otherwise, you can also build it from source (please see below) or
use it on a different path using `--with-elfutils=<PATH>`.


BUILD WITH ELFUTILS (libelf)
============================

It may be useful to manually compile libelf/libdw for uftrace build if the
target system doesn't have them installed.  `misc/install-elfutils.sh` provides
a way to download and build libelf and libdw, which are libraries in elfutils.

The below is the way to compile uftrace together with libelf/libdw.

    $ export CROSS_COMPILE=arm-linux-gnueabi-
    $ export ARCH=arm
    $ export CFLAGS="-march=armv7-a"
    $ ./misc/install-elfutils.sh --prefix=/path/to/install
    $ ./configure --prefix=/path/to/install --with-elfutils=/path/to/install

    $ make
    $ make install

`misc/install-elfutils.sh` downloads and builds elfutils and install both
libelf and libdw to prefix directory.  The installed libelf and libdw can be
found using `--with-elfutils` in `configure` script.
