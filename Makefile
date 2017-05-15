MODULE := duo-openvpn-standalone

module:
	go get
	go build -buildmode=c-shared -o ${MODULE}.so

clean:
	go clean
	-rm -f ${MODULE}.so ${MODULE}.h
	-docker-compose down

docker:
	docker-compose up --build

.PHONY: module clean docker
