
FROM rustlang/rust:nightly AS builder


WORKDIR /app

# Add musl support
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools ca-certificates && \
    rustup target add x86_64-unknown-linux-musl && \
    update-ca-certificates    

# Build static binary
COPY . .
RUN cargo build --release -p noon-server --locked --target x86_64-unknown-linux-musl

# Final stage
FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/noon-server /noon-server

# Copy CA certs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV PORT=39210
ENV RUST_LOG=info

EXPOSE $PORT

ENTRYPOINT ["/noon-server"]
