FROM centos:7
RUN yum install -y git gcc make epel-release
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY*
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN cd /usr/src/uftrace && ./misc/install-deps.sh -y && ./configure && make && make install
