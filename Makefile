.PHONY: all check clean

CFLAGS += -Wall -Wextra -Wpedantic
ifndef LIBS
LIBS   += -lssl -lcrypto -lgetdns
endif

all: main.o ocsp-stapling.o dnssec-chain-extension.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o openssl-demo-server $^ $(LIBS)

check:
	cppcheck --enable=all *.c *.h

clean:
	rm -f openssl-demo-server *.o
