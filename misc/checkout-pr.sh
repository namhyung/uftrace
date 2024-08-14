#!/bin/sh

if [ $# -ne "1" ]; then
	echo "usage: $0 <PR number>"
	exit 1
fi

if ! command -v curl > /dev/null 2>&1 || ! command -v jq > /dev/null 2>&1; then
	echo "You need both 'curl' and 'jq' to run this script."
	exit 1
fi

pr=$1
pr_json="pr.json"

curl -o $pr_json https://api.github.com/repos/namhyung/uftrace/pulls/$pr
repo=$(jq -r '.head.repo.html_url' $pr_json)
refspec=$(jq -r '.head.ref' $pr_json)
git fetch $repo $refspec && git checkout -B pull/$pr FETCH_HEAD
