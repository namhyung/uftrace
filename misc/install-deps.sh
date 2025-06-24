#!/bin/sh

install_packages() {
    case $1 in
        "ubuntu" | "debian")
            apt-get install $OPT pandoc libdw-dev python3-dev libncursesw5-dev pkg-config
            apt-get install $OPT libluajit-5.1-dev || true
            apt-get install $OPT libcapstone-dev || true
            apt-get install $OPT libtraceevent-dev || true
            exit
            ;;
        "fedora")
            dnf install $OPT pandoc elfutils-devel python3-devel ncurses-devel pkgconf-pkg-config
            dnf install $OPT luajit-devel || true
            dnf install $OPT capstone-devel || true
            dnf install $OPT libtraceevent-devel || true
            exit
            ;;
        "rocky")
            rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
            dnf install $OPT dnf-plugins-core
            dnf config-manager --set-enabled crb
            dnf install $OPT pandoc elfutils-devel python3-devel ncurses-devel pkgconfig
            dnf install $OPT luajit-devel || true
            dnf install $OPT capstone-devel || true
            dnf install $OPT libtraceevent-devel || true
            exit
            ;;
        "rhel" | "centos")
            rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
            yum install $OPT pandoc elfutils-devel python3-devel ncurses-devel pkgconfig
            yum install $OPT luajit-devel || true
            yum install $OPT capstone-devel || true
            dnf install $OPT libtraceevent-devel || true
            exit
            ;;
        "arch" | "manjaro")
            pacman $OPT -S pandoc libelf python3 ncurses pkgconf
            pacman $OPT -S luajit || true
            pacman $OPT -S capstone || true
            pacman $OPT -S libtraceevent || true
            exit
            ;;
        "alpine")
            apk add $OPT elfutils-dev python3-dev ncurses-dev pkgconf
            apk add $OPT luajit-dev || true
            apk add $OPT capstone-dev || true
            apk add $OPT libtraceevent-dev || true
            exit
            ;;
    esac
}

if [ "x$(id -u)" != x0 ]; then
    echo "You might have to run it as root user."
    echo "Please run it again with 'sudo'."
    echo
    exit
fi

OPT="${@}"

if [ ! -f /etc/os-release ]; then
    echo "Your distribution is not supported, so please install packages manually."
    echo
    exit
fi

distro=$(grep "^ID=" /etc/os-release | cut -d\= -f2 | sed -e 's/"//g')
id_like=$(grep "^ID_LIKE=" /etc/os-release | cut -d\= -f2 | sed -e 's/"//g')

install_packages "$distro"

for distro_like in $id_like; do
    install_packages "$distro_like"
done

echo "\"$distro\" is not supported distro, so please install packages manually."
echo
