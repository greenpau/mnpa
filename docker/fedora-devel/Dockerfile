#
# Build:   sudo docker build --no-cache --rm=true --force-rm=true -t greenpau/mnpa - < docker/fedora-devel/Dockerfile
#          sudo docker build -t greenpau/mnpa - < docker/fedora-devel/Dockerfile
# Run:     sudo docker run --rm -i -t --name=mnpa --privileged --cap-add all --net=host -v /tmp:/tmp  greenpau/mnpa /bin/bash
# Receive: mnpa --receiver eth1/239.1.2.4/5001/43200 --verbose
# Stream:  mnpa --threads 5 --sender eth1/10/64-255/1/0/239.1.2.3/5001/TEST1 --verbose --packet-storm
#

FROM fedora:latest
MAINTAINER Paul Greenberg @greenpau

RUN dnf -y install vim && dnf -y update
RUN dnf -y install zlib zlib-devel zlib-static bzip2 bzip2-libs bzip2-devel \
    ncurses ncurses-libs ncurses-devel ncurses-static readline readline-devel
RUN dnf -y install gdbm gdbm-devel sqlite sqlite-devel libxml2 libxml2-devel \
    libxml2-static libxslt libxslt-devel openssl openssl-devel openssl-static \
    openssl-libs wget xz xz-devel xz-libs pcre pcre-devel
RUN dnf -y install pcre-static pcre-tools libstdc++ libstdc++-devel libstdc++-static \
    libstdc++-docs json-devel libpqxx libpqxx-devel libyaml libyaml-devel \
    procps-ng procps-ng-devel libcap libcap-devel lsof libpcap libpcap-devel \
    kernel-devel man unzip git iproute sudo
RUN dnf -y install gcc gcc-c++ glibc* kernel-headers
RUN dnf -y install make
RUN cd /tmp && git clone https://github.com/greenpau/mnpa.git && cd mnpa && make && make install
