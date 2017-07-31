MODULE := duo-openvpn-standalone

module:
	go get
	go build
	go build -buildmode=c-shared -o ${MODULE}.so

clean:
	go clean
	-rm -f ${MODULE}.so ${MODULE}.h
	-docker-compose down
	$(MAKE) -C intermediary clean

install:
	go install

docker:
	docker-compose up --build

intermediary:
	$(MAKE) -C intermediary

docker_intermediary:
	docker-compose -f docker-compose.yml -f docker-compose-intermediary.yml up --build

.PHONY: module clean docker install intermediary docker_intermediary
