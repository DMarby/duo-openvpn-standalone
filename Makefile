MODULE := duo-openvpn-standalone

module:
	go build -buildmode=c-shared -o ${MODULE}.so

clean:
	go clean
	-rm -f ${MODULE}.so ${MODULE}.h

.PHONY: module clean
