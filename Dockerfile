FROM golang:1.7

RUN apt-get update && \
  apt-get install -y \
  openvpn

ENV GOPATH /opt/go:$GOPATH
ENV PATH /opt/go/bin:$PATH
ADD . /opt/go/src/local/DMarby/duo-openvpn-standalone
WORKDIR /opt/go/src/local/DMarby/duo-openvpn-standalone

RUN make

WORKDIR /etc/openvpn

COPY openvpn ./

CMD ["./openvpn.sh"]
