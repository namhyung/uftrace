#!/bin/sh

if [ "x$(id -u)" != x0 ]; then
    echo "You might have to run it as root user."
    echo "Please run it again with 'sudo'."
    echo
    return
fi

apt-get install pandoc libdw-dev libpython2.7-dev libncursesw5-dev
