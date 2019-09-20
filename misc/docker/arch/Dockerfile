FROM archlinux/base:latest
RUN pacman -Sy
RUN yes | pacman -S git gcc make
RUN mkdir -p /usr/src
RUN git clone https://github.com/namhyung/uftrace /usr/src/uftrace
RUN cd /usr/src/uftrace && yes | ./misc/install-deps.sh && ./configure && make && make install
