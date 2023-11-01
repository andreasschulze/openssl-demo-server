# openssl-demo-server

Example program to implement a TLS server. It was written for demonstration and
educational purposes.

## Pre-requisites

- [OpenSSL](https://openssl.org) version 1.1.0 or later
- [getdns library](https://getdnsapi.net/)

## Features

- OCSP stapling
- DNSSEC Authentication chain extension
- session resumption
- 4 x 100 at [SSLlabs](https://ssllabs.com/ssltest/) given a valid key and
  certificate is used
- chroot operation possible
- setuid(non root user) possible

## Limitations

- can't specify to listen in IPv4 only if IPv6 is available
- proxy-mode: destination must be an IPv4 address

## Source

- based on sample code "Simple_TLS_Server" from [https://wiki.openssl.org/](https://wiki.openssl.org/)
- DNSSEC Authentication chain extension based on the implementation of Shumon
  Huque available at [https://github.com/shuque/chainserver](https://github.com/shuque/chainserver)
- session resumption worked after I read [https://nachtimwald.com/2014/10/05/server-side-session-cache-in-openssl/](https://nachtimwald.com/2014/10/05/server-side-session-cache-in-openssl/)
- OCSP implementation was copied from [nginx](https://github.com/nginx/nginx/blob/master/src/event/ngx_event_openssl_stapling.c)

## general Build

```sh
make
cc -Wall -Wextra -Wpedantic -c -o main.o main.c
cc -Wall -Wextra -Wpedantic -c -o ocsp-stapling.o ocsp-stapling.c
cc -Wall -Wextra -Wpedantic -c -o dnssec-chain-extension.o dnssec-chain-extension.c
cc -Wall -Wextra -Wpedantic -lssl -lcrypto -lgetdns -o openssl-demo-server \
  main.o ocsp-stapling.o dnssec-chain-extension.o
...
```

## personal Build

```sh
DEB_BUILD_MAINT_OPTIONS='hardening=+all'
CFLAGS="$( dpkg-buildflags --get CFLAGS ) $( dpkg-buildflags --get CPPFLAGS )"
LDFLAGS="$( dpkg-buildflags --get LDLAGS )"
LIBS='-lssl-dv -lcrypto-dv -lgetdns'
export DEB_BUILD_MAINT_OPTIONS CFLAGS LDFLAGS LIBS
make -B
```

## Docker Build

```sh
docker build -t openssl-demo-server .

OR

docker-compose build
```

## Usage

```sh
# /path/to/openssl-demo-server -h

Usage: openssl-demo-server [options]

  -h                  print this help message
  -sname  <name>      server name               default: openssl-demo-server.example
  -port   <port>      server port               default: 443
  -cert   <file>      server certificate file   default: ./cert+intermediate.pem
  -key    <file>      server private key file   default: ./key.pem
  -oscp   <file>      server ocsp response file default: ./ocsp.response
  -chroot <dir>       chroot to directory       default: don't chroot
  -user   <name>      switch to that user       default: don't switch user
  -proxy  <ip>:<port> IPv4 address and port to forward to
```

If the program cannot access the OCSP response file OCSP will be not used.

## Bugs

I'm sure there are some! For that reason: DO NOT USE that software on a
production level system!
