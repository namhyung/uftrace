#!/bin/bash

info_file=coverage.info
report_dir=coverage.html
with_branch=0

which lcov > /dev/null
lcov_test=$?
if [ 0 -ne $lcov_test ]; then
	echo "Error: cannot find 'lcov': Please install it first."
	exit $lcov_test
fi

usage() {
    echo "Usage: $0 [<options>]

  -h          print this message
  -o <DIR>    set output report dir as <DIR>            (default: coverage.html)
  -b          generate the report with branch coverage  (default: off)
"
    exit 1
}

while getopts "o:bh" opt
do
    case "$opt" in
        o) report_dir=$OPTARG ;;
	b) with_branch=1 ;;
	h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

if [ $with_branch -eq 1 ]; then
    lcov --capture --rc lcov_branch_coverage=1 --directory . --output-file $info_file
    genhtml $info_file --branch-coverage --output-directory $report_dir
else
    lcov --capture --directory . --output-file $info_file
    genhtml $info_file --output-directory $report_dir
fi
rm -f $info_file

rmdir $report_dir 2> /dev/null

if [ -d $report_dir ]; then
  echo -e "\nThe code coverage report is normally generated in $report_dir\n"
fi
