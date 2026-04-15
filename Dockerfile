# Stage 1: Build
# Using the Alpine-based Rust image to ensure we build against musl
FROM rust:1.91-alpine AS builder

# Install build dependencies for Rust compilation
RUN apk add --no-cache \
    musl-dev \
    binutils \
    git

WORKDIR /usr/src/noon

# Copy workspace configuration and lockfile first to leverage Docker cache
# However, since it's a multi-crate workspace, we copy the relevant crates too
COPY Cargo.toml Cargo.lock ./
COPY proto/ ./proto/
COPY crates/ ./crates/

# Build the server crate in release mode
# --locked ensures the build uses the exact versions in Cargo.lock
RUN cargo build --release -p noon-server --locked

# Strip the binary to remove debug symbols and reduce size significantly
RUN strip target/release/noon-server

# Stage 2: Runtime
# Using alpine for a minimal (~5MB) but functional base image
FROM alpine:latest

# Install CA certificates for secure outgoing requests (e.g., sending emails or API calls)
RUN apk add --no-cache ca-certificates

# Create a non-root user for security best practices
RUN addgroup -S noon && adduser -S noon -G noon

WORKDIR /app

# Copy the static binary from the builder stage
COPY --from=builder /usr/src/noon/target/release/noon-server /app/noon-server

# Ensure the binary has the correct permissions
RUN chown noon:noon /app/noon-server

# Switch to the non-root user
USER noon

# Default port for the noon server
EXPOSE 39210

# Set environment variables if needed
ENV PORT=39210
ENV RUST_LOG=info

# Run the server
CMD ["./noon-server"]
