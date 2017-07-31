FROM golang:1.7

RUN apt-get update && \
  apt-get install -y \
  openvpn

ENV GOPATH /opt/go:$GOPATH
ENV PATH /opt/go/bin:$PATH
ADD . /opt/go/src/local/DMarby/duo-openvpn-standalone
WORKDIR /opt/go/src/local/DMarby/duo-openvpn-standalone

RUN make
RUN make intermediary

WORKDIR /etc/openvpn

COPY docker/openvpn ./
COPY docker/duo-openvpn-standalone.yml /etc/duo-openvpn-standalone.yml

CMD ["./openvpn.sh", "/etc/openvpn/server.conf"]
