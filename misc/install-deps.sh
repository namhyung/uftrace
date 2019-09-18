#!/bin/sh

if [ "x$(id -u)" != x0 ]; then
    echo "You might have to run it as root user."
    echo "Please run it again with 'sudo'."
    echo
    exit
fi

OPT="${@}"

distro=$(grep "^ID=" /etc/os-release | cut -d\= -f2 | sed -e 's/"//g')

case $distro in
    "ubuntu" | "debian")
        apt-get $OPT install pandoc libdw-dev libpython2.7-dev libncursesw5-dev pkg-config
        apt-get $OPT install libcapstone-dev ;;
    "fedora")
        dnf install $OPT pandoc elfutils-devel python2-devel ncurses-devel pkgconf-pkg-config
        dnf install $OPT capstone-devel ;;
    "rhel" | "centos")
        rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
        yum install $OPT pandoc elfutils-devel python2-devel ncurses-devel pkgconfig
        yum install $OPT capstone-devel ;;
    "arch")
	pacman $OPT -S pandoc libelf python2 ncurses pkgconf
	pacman $OPT -S capstone ;;
    *) # we can add more install command for each distros.
        echo "\"$distro\" is not supported distro, so please install packages manually." ;;
esac

