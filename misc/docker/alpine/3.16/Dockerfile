FROM alpine:3.16
ARG test
RUN apk update
RUN apk add build-base linux-headers git bash libunwind-dev
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN if [ "${test}" == "yes" ] ; then \
        cd /usr/src/uftrace && ./misc/install-deps.sh && ./configure && make && make unittest; \
    else \
        cd /usr/src/uftrace && ./misc/install-deps.sh && ./configure && make && make install; \
    fi
