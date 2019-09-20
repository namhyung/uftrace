FROM ubuntu:18.04
RUN apt-get update \
&& apt-get install -y --no-install-recommends git gcc make ca-certificates
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN cd /usr/src/uftrace && yes | ./misc/install-deps.sh && ./configure && make && make install
RUN apt-get clean \
&& rm -rf /var/lib/apt/lists/*
