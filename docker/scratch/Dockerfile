#
# Build: sudo docker build -t greenpau/mnpa:scratch .
# Run:   sudo docker run --rm greenpau/mnpa:scratch
#

FROM scratch
MAINTAINER Paul Greenberg @greenpau
COPY ./mnpa /sbin/mnpa
ENTRYPOINT ["/sbin/mnpa"]
