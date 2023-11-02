#!/bin/sh

if [ $# -ne "1" ]; then
	echo "usage: $0 <PR number>"
	exit 1
fi

pr=$1

if command -v wget &> /dev/null; then
    wget https://github.com/namhyung/uftrace/pull/$pr.patch
elif command -v curl &> /dev/null; then
    curl -L https://github.com/namhyung/uftrace/pull/$pr.patch > $pr.patch
else
    echo "You need wget or curl to run this script."
fi
