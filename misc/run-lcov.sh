#!/bin/bash

report_dir=coverage.html

if [ $# -eq 1 ]; then
  report_dir=$1
fi

which lcov > /dev/null
lcov_test=$?
if [ 0 -ne $lcov_test ]; then
	echo "Error: cannot find 'lcov': Please install it first."
	exit $lcov_test
fi

info_file=coverage.info
lcov --capture --rc lcov_branch_coverage=1 --directory . --output-file $info_file
genhtml $info_file --branch-coverage --output-directory $report_dir
rm -f $info_file

rmdir $report_dir 2> /dev/null

if [ -d $report_dir ]; then
  echo -e "\nThe code coverage report is normally generated in $report_dir\n"
fi
