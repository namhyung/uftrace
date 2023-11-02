#!/bin/sh

if [ $# -ne "1" ]; then
	echo "usage: $0 <PR number>"
	exit 1
fi

pr=$1

if [ -x "$(command -v wget)" ]; then
    wget https://github.com/namhyung/uftrace/pull/$pr.patch
    exit 0
elif [ -x "$(command -v curl)" ]; then
    curl -L https://github.com/namhyung/uftrace/pull/$pr.patch > $pr.patch
    exit 0
else
    echo "You need wget or curl to run this script."
    exit 1
fi
