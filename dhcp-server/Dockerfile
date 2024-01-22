FROM rust:alpine as builder

RUN apk add musl-dev g++ openssl-dev
WORKDIR /app
COPY . .

RUN cargo build --release

FROM scratch
WORKDIR /

COPY --from=builder /app/target/release/rust-dhcp /rust-dhcp
COPY config.toml /config.toml

ENTRYPOINT ["/rust-dhcp"]
