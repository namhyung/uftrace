#!/bin/sh

srcdir=$(git rev-parse --show-toplevel)
docdir=$srcdir/doc

spell --print-file-name --number --dictionary $docdir/dictionary.txt $srcdir/*.md
spell --print-file-name --number --dictionary $docdir/dictionary.txt $docdir/*.md
