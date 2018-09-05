#!/bin/bash
#-*- mode: shell-script; -*-

prefix=/usr/local

objdir=$(readlink -f ${objdir:-${PWD}})
builddir=${objdir}/.build

n_cpus=$(grep -c ^processor /proc/cpuinfo)

usage() {
    echo "Usage: $0 [<options>]

  --help             print this message
  --prefix=<DIR>     set install root dir as <DIR>        (default: /usr/local)

  Example usage for host compilation:
    $ $0 --prefix=./build.host

  Example usage for cross compilation:
    $ CROSS_COMPILE=arm-linux-gnueabi- ARCH=arm CFLAGS=\"-march=armv7-a\" \\
        $0 --prefix=./build.arm
"
    exit 1
}

while getopts ":ho:-:p" opt; do
    case "$opt" in
        -)
	    # process --long-options
	    case "$OPTARG" in
                help)  usage ;;
                *=*)   opt=${OPTARG%%=*}; val=${OPTARG#*=}
                       eval "${opt/-/_}='$val'" ;;
                *)     ;;
            esac
	    ;;
        *)       usage ;;
    esac
done
shift $((OPTIND - 1))

mkdir -p ${builddir} && cd ${builddir}

ELFUTILS_VERSION=0.164
ELFUTILS_NAME=elfutils-$ELFUTILS_VERSION
ELFUTILS_TARBALL=$ELFUTILS_NAME.tar.bz2
ELFUTILS_URL=https://sourceware.org/elfutils/ftp/$ELFUTILS_VERSION/$ELFUTILS_TARBALL

if [ ! -d "$ELFUTILS_NAME" ]; then
    wget -c $ELFUTILS_URL
    tar xvfj $ELFUTILS_TARBALL
    ln -sf $ELFUTILS_NAME elfutils
fi
cd elfutils

opt_host_cc=""
if [ ! -z $CROSS_COMPILE ]; then
    HOST=$(basename $CROSS_COMPILE | sed 's/-$//g')
    opt_host_cc="--host=$HOST CC=${CROSS_COMPILE}gcc"
fi

configure_cmd="./configure --prefix=$prefix $opt_host_cc"
if [ ! -f configure.cmd ] || [ "$configure_cmd" != "$(cat configure.cmd)" ]; then
    $configure_cmd && echo "$configure_cmd" > configure.cmd
fi

# build and install libelf first
make -j${n_cpus} -C libelf install

# build and install libdw later on
#   libdw requires to build libdwfl, libdwelf, and libebl
make -j${n_cpus} -C libdwfl
make -j${n_cpus} -C libdwelf
make -j${n_cpus} -C libebl CFLAGS="$CFLAGS -Wno-misleading-indentation"
make -j${n_cpus} -C libdw install

cd ..
