.PHONY: clean install uninstall test binary
ifndef CXX
	CXX=g++
endif

BINARY:="mnpa"
CFLAGS=-std=c++11
INCLUDES=
LFLAGS=-static-libgcc -static-libstdc++
LIBS=-pthread -lpthread
IFNAME=eth1

ifdef type
  ifeq (${type},static)
    override CFLAGS+= -g -Wall -O3
    override LFLAGS+= -static -static-libgcc -static-libstdc++
  endif
  ifeq (${type},travis)
    override CFLAGS+= -g -Wall -O3 -g -pedantic
    override IFNAME=venet0
  endif
endif

.PHONY: all clean install uninstall test

all: clean binary

binary:
	@printf "compiling ${BINARY} with ${CXX} ...";
	@mkdir -p bin;
	@${CXX} -v ${CFLAGS} ${LFLAGS} ${INCLUDES} main.cpp -o bin/${BINARY} ${LIBS};
	@printf " OK!\n";

install:
	@printf "installing ${BINARY} ...\n";
	@sudo cp bin/${BINARY} /sbin/${BINARY};

uninstall:
	@printf "uninstalling ${BINARY} ...\n";
	@sudo rm -rf /sbin/${BINARY};

clean:
	@printf "running cleanup ...\n";
	@rm -rf bin/* *.o
    
test:
	@printf "testing ...\n";
	@sudo $(CURDIR)/bin/${BINARY} --threads 5 --sender ${IFNAME}/5/64-127/60/0/224.0.0.1/5001/TEST1 \
        --sender ${IFNAME}/50/64-127/60/0/224.0.0.2/5001/TEST2 -p -20 --verbose --non-root
