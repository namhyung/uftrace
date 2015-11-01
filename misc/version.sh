#!/bin/sh

VERSION_FILE=version.h

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

CURR_VERSION=$1
FILE_VERSION=
GIT_VERSION=

if test -f ${VERSION_FILE}; then
    FILE_VERSION=$(cat ${VERSION_FILE} 2>/dev/null | cut -d'"' -f2)
fi

if test -d .git -a -x `which git`; then
    # update current version using git tags
    GIT_VERSION=`git describe --tags --abbrev=4 --match="v[0-9].[0-9]*" 2>/dev/null`
    CURR_VERSION=${GIT_VERSION}
fi

if test -z "${GIT_VERSION}" -a -n "${FILE_VERSION}"; then
    # do not update file version if git version is not avaiable
    exit 0
fi

if test "${CURR_VERSION}" != "${FILE_VERSION}"; then
    # update file version only if it's different
    echo "#define FTRACE_VERSION  \"${CURR_VERSION}\"" > ${VERSION_FILE}
    exit 0
fi
