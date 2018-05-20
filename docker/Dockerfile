FROM golang:1.10

RUN echo 'deb http://ftp.debian.org/debian stretch-backports main' >> /etc/apt/sources.list

RUN apt-get update && \
  apt-get install -y -t stretch-backports \
  openvpn

ENV GOPATH /opt/go:$GOPATH
ENV PATH /opt/go/bin:$PATH
ADD . /opt/go/src/local/DMarby/duo-openvpn-standalone
WORKDIR /opt/go/src/local/DMarby/duo-openvpn-standalone

RUN go get -u github.com/golang/dep/cmd/dep

RUN make
RUN make intermediary

WORKDIR /etc/openvpn

COPY docker/openvpn ./
COPY docker/duo-openvpn-standalone.yml /etc/duo-openvpn-standalone.yml

CMD ["./openvpn.sh", "/etc/openvpn/server.conf"]
