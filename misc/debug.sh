#!/bin/sh

TMP=$(mktemp)
ARGV="${@:-tests/t-abc}"

sed "s|argv|$ARGV|g" misc/debug-mcount.cmd > $TMP

gdb -x $TMP

rm -f $TMP

