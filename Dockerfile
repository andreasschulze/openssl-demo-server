FROM debian:bookworm-slim AS builder
WORKDIR /openssl-demo-server/
COPY . ./
RUN    apt-get -qq update \
    && apt-get -qq --no-install-recommends install \
         cppcheck \
         gcc \
         libc6-dev \
         libgetdns-dev \
         libssl-dev \
         make \
    && make \
    && make check \
    && strip openssl-demo-server

FROM debian:bookworm-slim
COPY --from=builder /openssl-demo-server/openssl-demo-server /usr/local/bin/
RUN    chmod 0555 /usr/local/bin/openssl-demo-server \
    && apt-get -qq update \
    && apt-get -qq --no-install-recommends install \
         libgetdns10 \
    && apt-get -qq clean \
    && rm -f /var/lib/apt/lists/deb*

ENTRYPOINT [ "/usr/local/bin/openssl-demo-server" ]
CMD [ "-h" ]
