# openssl-demo-server

Example program to implement a TLS server. It was written for demonstration and educational purposes.

## Pre-requisites:
 - [OpenSSL](https://openssl.org) version 1.1.0 or later
 - [getdns library](https://getdnsapi.net/), for getdns version

## Features:
 - OCSP stapling
 - DNSSEC Authentication chain extension
 - session resumption
 - 4 x 100 at [SSLlabs](https://ssllabs.com/ssltest/) given the right key and certificate

## Source:
 - based on sample code "Simple_TLS_Server" from https://wiki.openssl.org/
 - DNSSEC Authentication chain extension based on the implementation of Shumon Huque available at https://github.com/shuque/chainserver
 - session resumption worked after I read https://nachtimwald.com/2014/10/05/server-side-session-cache-in-openssl/

## Build:
```
$ make
cc -Wall -Wextra -Wpedantic   -c -o main.o main.c
cc -Wall -Wextra -Wpedantic   -c -o ocsp-stapling.o ocsp-stapling.c
cc -Wall -Wextra -Wpedantic   -c -o dnssec-chain-extension.o dnssec-chain-extension.c
cc -Wall -Wextra -Wpedantic  -lssl -lcrypto -lgetdns -o openssl-demo-server main.o ocsp-stapling.o dnssec-chain-extension.o
```

## Usage:
```
# /path/to/openssl-demo-server -h

Usage: openssl-demo-server [options]

  -h:             print this help message
  -sname <name>   server name               default: $(fqdn)
  -port  <port>   server port               default: 443
  -cert  <file>   server certificate file   default: ./cert+intermediate.pem
  -key   <file>   server private key file   default: ./key.pem
  -oscp  <file>   server ocsp response file default: ./ocsp.response
```

It the program cannot access the OCSP response file OCSP will be not used.

## Bugs:
I'm sure there are some ...
For that DO NOT USE that software on a production level system.
