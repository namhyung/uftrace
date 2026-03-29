FROM ubuntu:18.04
ARG test
RUN apt-get update \
    && apt-get install -y --no-install-recommends git gcc make ca-certificates
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN if [ "$test" = "yes" ] ; then \
        cd /usr/src/uftrace \
        && ./misc/install-deps.sh -y \
        && ./configure && make ASAN=1 && make install && make ASAN=1 unittest; \
    else \
        cd /usr/src/uftrace && ./misc/install-deps.sh -y && ./configure && make && make install; \
    fi
RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/*
