FROM rust:1.94.0-alpine3.23 AS build
RUN apk add --no-cache build-base cmake perl sqlite-dev
WORKDIR /src
ENV RUSTFLAGS="-C target-feature=-crt-static"
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY client/Cargo.toml client/Cargo.toml
COPY libfec/Cargo.toml libfec/Cargo.toml
COPY shared shared
COPY server server
# Cargo resolves all workspace manifests, including packages not being built.
RUN mkdir -p client/src libfec/src && touch client/src/main.rs libfec/src/lib.rs
RUN cargo build --locked --release -p cat4igp-server && strip target/release/cat4igp-server

FROM alpine:3.23
RUN apk add --no-cache ca-certificates libgcc sqlite-libs \
    && addgroup -S -g 10001 cat4igp \
    && adduser -S -D -H -u 10001 -G cat4igp cat4igp \
    && mkdir /data && chown cat4igp:cat4igp /data && chmod 0700 /data
COPY --from=build /src/target/release/cat4igp-server /usr/bin/cat4igp-server
COPY LICENSE /usr/share/licenses/cat4igp/LICENSE
ENV DATABASE_URL=/data/cat4igp.db
WORKDIR /data
USER 10001:10001
ENTRYPOINT ["/usr/bin/cat4igp-server"]