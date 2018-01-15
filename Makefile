.PHONY: all clean

CFLAGS += -Wall -Wextra -Wpedantic
ifndef LIBS
LIBS   += -lssl -lcrypto -lgetdns
endif

all: main.o ocsp-stapling.o dnssec-chain-extension.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o openssl-demo-server $^ $(LIBS)

clean:
	rm -f openssl-demo-server *.o
