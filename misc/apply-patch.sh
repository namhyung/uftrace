#!/bin/sh

unexpand $1 | sed -e "s/^\t/ \t/" | patch -p1
