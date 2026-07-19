FROM rockylinux:8
ARG test
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY*
RUN dnf --enablerepo=powertools install -y pandoc
RUN dnf install -y gcc gcc-c++ git make libasan libubsan epel-release
RUN dnf install -y elfutils-devel python3-devel ncurses-devel luajit-devel capstone-devel
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN if [ "$test" = "yes" ] ; then \
        cd /usr/src/uftrace \
        && ./misc/install-deps.sh -y \
        && ./configure && make ASAN=1 && make ASAN=1 unittest; \
    else \
        cd /usr/src/uftrace && ./misc/install-deps.sh -y && ./configure && make && make install; \
    fi
