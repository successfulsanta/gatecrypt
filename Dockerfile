FROM ubuntu:24.04 AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake libssl-dev python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j"$(nproc)" && \
    ./build/gatecrypt_tests

FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -s /usr/sbin/nologin gatecrypt \
    && mkdir -p /data /etc/gatecrypt && chown gatecrypt:gatecrypt /data
COPY --from=build /src/build/gatecryptd /usr/local/bin/gatecryptd
COPY --from=build /src/build/gatecrypt-issue /usr/local/bin/gatecrypt-issue
COPY --from=build /src/config/gatecrypt.conf.example /etc/gatecrypt/gatecrypt.conf
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/gatecryptd", "-c", "/etc/gatecrypt/gatecrypt.conf"]
