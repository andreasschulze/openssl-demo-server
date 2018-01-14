.PHONY: all clean

CFLAGS += -Wall -Wextra -Wpedantic
ifndef LIBS
LIBS   += -lssl -lcrypto -lgetdns
endif

all: main.o ocsp-stapling.o dnssec-chain-extension.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -o openssl-demo-server $^

clean:
	rm -f openssl-demo-server *.o
