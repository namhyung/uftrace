FROM opensuse/leap:15
ARG test
RUN zypper install -y gcc git make
RUN zypper install -y pandoc libdw-devel python3-devel ncurses-devel pkg-config libstdc++-devel
RUN zypper install -y luajit-devel libcapstone-devel
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN if [ "$test" = "yes" ] ; then \
        cd /usr/src/uftrace \
        && ./misc/install-deps.sh -y \
        && ./configure && make ASAN=1 && make ASAN=1 unittest; \
    else \
        cd /usr/src/uftrace && ./misc/install-deps.sh -y && ./configure && make && make install; \
    fi
