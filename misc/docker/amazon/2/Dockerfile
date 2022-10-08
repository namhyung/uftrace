FROM amazonlinux:2
ARG test

RUN yum update -y
RUN yum -y  groupinstall "Development Tools"
ADD install-deps.sh install-deps.sh
RUN bash install-deps.sh -y
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN if [ "$test" = "yes" ] ; then \
        cd /usr/src/uftrace \
        && ./configure && make ASAN=1 && make ASAN=1 unittest; \
    else \
        cd /usr/src/uftrace && ./configure && make && make install; \
    fi
