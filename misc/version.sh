#!/bin/sh

VERSION_FILE=$1

if [ $# -ne 2 ]; then
    echo "Usage: $0 <filename> <version>"
    exit 1
fi

CURR_VERSION=$2
FILE_VERSION=
GIT_VERSION=

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

if test -z "${FILE_VERSION}" -o "${CURR_VERSION}" != "${FILE_VERSION}"; then
    # update file version only if it's different
    echo "#define UFTRACE_VERSION  \"${CURR_VERSION}\"" > ${VERSION_FILE}
    echo "  GEN     " ${VERSION_FILE#${objdir}/}
    exit 0
fi
