FROM centos:8
ARG test

# setting package manager
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY*
RUN dnf install -y 'dnf-command(config-manager)'
RUN dnf config-manager --set-enabled powertools

RUN dnf -y install gcc gcc-c++ git make libasan libubsan
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN if [ "$test" = "yes" ] ; then \
        cd /usr/src/uftrace \
        && ./misc/install-deps.sh -y \
        && ./configure && make ASAN=1 && make ASAN=1 unittest; \
    else \
        cd /usr/src/uftrace && ./misc/install-deps.sh -y && ./configure && make && make install; \
    fi
