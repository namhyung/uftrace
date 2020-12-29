#!/bin/sh

VERSION_FILE=$1

if [ $# -ne 4 ]; then
    echo "Usage: $0 <filename> <version> <arch> <srcdir>"
    exit 1
fi

CURR_VERSION=$2
FILE_VERSION=
GIT_VERSION=

ARCH=$3

SRCDIR=$4

if test -f ${VERSION_FILE}; then
    FILE_VERSION=$(cut -d'"' -f2 ${VERSION_FILE})
fi

if test -d .git -a -n "$(git --version 2>/dev/null)"; then
    # update current version using git tags
    GIT_VERSION=$(git describe --tags --abbrev=4 --match="v[0-9].[0-9]*" 2>/dev/null)
    CURR_VERSION=${GIT_VERSION}
fi

if test -z "${GIT_VERSION}" -a -n "${FILE_VERSION}"; then
    # do not update file version if git version is not avaiable
    exit 0
fi

DEPS=" ${ARCH}"
if test -f ${SRCDIR}/check-deps/have_libdw; then
    DEPS="${DEPS} dwarf"
fi
if test -f ${SRCDIR}/check-deps/have_libpython2.7; then
    DEPS="${DEPS} python"
fi
if test -f ${SRCDIR}/check-deps/have_libluajit; then
    DEPS="${DEPS} luajit"
fi
if test -f ${SRCDIR}/check-deps/have_libncurses; then
    DEPS="${DEPS} tui"
fi
if test -f ${SRCDIR}/check-deps/perf_clockid; then
    DEPS="${DEPS} perf"
fi
if test -f ${SRCDIR}/check-deps/perf_context_switch; then
    DEPS="${DEPS} sched"
fi
if test -f ${SRCDIR}/check-deps/have_libcapstone; then
    DEPS="${DEPS} dynamic"
fi
if [ "x${DEPS}" != "x" ]; then
    DEPS=" (${DEPS} )"
fi

if test -z "${FILE_VERSION}" -o "${CURR_VERSION}${DEPS}" != "${FILE_VERSION}"; then
    # update file version only if it's different
    echo "#define UFTRACE_VERSION  \"${CURR_VERSION}${DEPS}\"" > ${VERSION_FILE}
    echo "  GEN     " ${VERSION_FILE#${objdir}/}
    exit 0
fi
