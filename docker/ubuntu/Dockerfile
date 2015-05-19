#
# Build:   sudo docker build --no-cache --rm=true --force-rm=true -t greenpau/mnpa - < docker/ubuntu/Dockerfile
# Run:     sudo docker run --rm -i -t --name=mnpa --privileged --cap-add all --net=host -v /tmp:/tmp  greenpau/mnpa /bin/bash
# Receive: mnpa --receiver eth1/239.1.2.4/5001/43200 --verbose
# Stream:  mnpa --threads 5 --sender eth1/10/64-255/1/0/239.1.2.3/5001/TEST1 --verbose --packet-storm
#

FROM ubuntu

MAINTAINER Paul Greenberg @greenpau

RUN apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 3B4FE6ACC0B21F32 && \
 apt-get install -y software-properties-common && \
 apt-add-repository -y "deb http://archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse" && \
 apt-add-repository -y ppa:ubuntu-toolchain-r/test && \
 apt-get update -qq && \
 apt-get install -qq gcc-5 g++-5 make git vim && \
 update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-5 500

RUN cd /tmp && cd mnpa || git clone https://github.com/greenpau/mnpa.git && cd mnpa && make && make install
