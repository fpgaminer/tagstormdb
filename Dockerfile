# Build Rust API
FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev make

WORKDIR /usr/src/rust-api
COPY src ./src
COPY Cargo.* ./
COPY tag_blacklist20231201.txt ./
COPY tag_deprecations20231201.txt ./
COPY tag_aliases000000000000.json ./
COPY tag_implications000000000000.json ./

RUN cargo install --path .


# Build the final image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates

WORKDIR /root

COPY --from=builder /usr/local/cargo/bin/server /usr/local/bin/server

ENV SERVER_IP=0.0.0.0
ENV SERVER_PORT=8086
ENV PREDICTION_SERVER=http://127.0.0.1:8087
ENV IMAGE_DIR=images
ENV UPLOAD_DIR=uploads
ENV DB_DIR=db
ENV SECRETS_PATH=db/secrets.json

CMD ["server"]