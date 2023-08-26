#!/bin/sh

if [ $# -ne "1" ]; then
	echo "usage: $0 <PR number>"
	exit 1
fi

pr=$1
wget https://github.com/namhyung/uftrace/pull/$pr.patch
