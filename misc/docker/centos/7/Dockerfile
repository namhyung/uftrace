FROM centos:7
ARG test
RUN yum install -y git gcc make epel-release
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY*

# update gcc  version
RUN yum install -y centos-release-scl
RUN yum install -y devtoolset-9-gcc* devtoolset-9-libasan-devel devtoolset-9-libubsan-devel
RUN echo "source /opt/rh/devtoolset-9/enable" >> /etc/bashrc
SHELL ["/bin/bash", "--login", "-c"]

RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN if [ "$test" = "yes" ] ; then \
        cd /usr/src/uftrace \
        && ./misc/install-deps.sh -y \
        && ./configure && make ASAN=1 && make install && make ASAN=1 unittest; \
    else \
        cd /usr/src/uftrace && ./misc/install-deps.sh -y && ./configure && make && make install; \
    fi
