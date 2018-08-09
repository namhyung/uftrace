#!/bin/sh

VERSION_FILE=$1

if [ $# -ne 3 ]; then
    echo "Usage: $0 <filename> <version> <srcdir>"
    exit 1
fi

CURR_VERSION=$2
FILE_VERSION=
GIT_VERSION=

SRCDIR=$3

if test -f ${VERSION_FILE}; then
    FILE_VERSION=$(cat ${VERSION_FILE} 2>/dev/null | cut -d'"' -f2)
fi

if test -d .git -a -n "`git --version 2>/dev/null`"; then
    # update current version using git tags
    GIT_VERSION=`git describe --tags --abbrev=4 --match="v[0-9].[0-9]*" 2>/dev/null`
    CURR_VERSION=${GIT_VERSION}
fi

if test -z "${GIT_VERSION}" -a -n "${FILE_VERSION}"; then
    # do not update file version if git version is not avaiable
    exit 0
fi

DEPS=""
if test -f ${SRCDIR}/check-deps/have_libdw; then
    DEPS="${DEPS} dwarf"
fi
if test -f ${SRCDIR}/check-deps/have_libpython2.7; then
    DEPS="${DEPS} python"
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
if [ "x${DEPS}" != "x" ]; then
    DEPS=" (${DEPS} )"
fi

if test -z "${FILE_VERSION}" -o "${CURR_VERSION}${DEPS}" != "${FILE_VERSION}"; then
    # update file version only if it's different
    echo "#define UFTRACE_VERSION  \"${CURR_VERSION}${DEPS}\"" > ${VERSION_FILE}
    echo "  GEN     " ${VERSION_FILE#${objdir}/}
    exit 0
fi
