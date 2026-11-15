FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates \
        libsqlite3-dev libssl-dev libasound2t64 libpulse0 libx11-6 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src
COPY tests ./tests
COPY third_party ./third_party
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build \
    && ctest --test-dir build --output-on-failure

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        libasound2t64 libpulse0 libx11-6 libatomic1 ca-certificates \
        libsqlite3-0 libssl3 \
    && rm -rf /var/lib/apt/lists/*
# The ubuntu image already ships user "ubuntu" with uid 1000, the usual owner of ./data on the host.
COPY --from=build /src/build/relay /src/build/libdiscord_partner_sdk.so /opt/relay/
RUN mkdir /data && chown ubuntu:ubuntu /data
USER ubuntu
ENV DATA_DIR=/data HOME=/data
VOLUME /data
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/opt/relay/relay"]
