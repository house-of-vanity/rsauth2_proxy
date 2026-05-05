FROM rust:1-slim AS builder

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/rsauth2-proxy /rsauth2-proxy
ENTRYPOINT ["/rsauth2-proxy"]
