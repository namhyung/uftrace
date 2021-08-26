FROM alpine:3.14
RUN apk update
RUN apk add build-base linux-headers git bash libunwind-dev
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN cd /usr/src/uftrace && ./misc/install-deps.sh && ./configure && make && make install
