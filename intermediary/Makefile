INTERMEDIARY := intermediary

build: intermediary.so

intermediary.o: intermediary.cpp
	$(CC) $(CFLAGS) -fPIC -std=c++11 -I../lib/openvpn/include -c intermediary.cpp

intermediary.so: intermediary.o
	$(CC) -fPIC -std=c++11 -shared -Wl,-soname,intermediary.so -o intermediary.so intermediary.o -lc

clean:
	-rm -f ${INTERMEDIARY}.so

.PHONY: build
