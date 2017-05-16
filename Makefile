MODULE := duo-openvpn-standalone

module:
	go get
	go build
	go build -buildmode=c-shared -o ${MODULE}.so

clean:
	go clean
	-rm -f ${MODULE}.so ${MODULE}.h
	-docker-compose down

install:
	go install

docker:
	docker-compose up --build

.PHONY: module clean docker install
