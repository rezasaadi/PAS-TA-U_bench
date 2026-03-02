FROM rust:1.76-slim

WORKDIR /app

# Cache deps first
COPY Cargo.toml Cargo.toml
RUN mkdir -p src/protocols src/bin && \
    echo "pub fn _dummy(){}" > src/lib.rs && \
    echo "fn main(){}" > src/bin/bench_pastau.rs && \
    cargo build --release && \
    rm -rf src

# Now copy real sources
COPY src src
COPY README.md README.md

RUN cargo build --release

# Default: run the benchmark (you can override args with `docker run ... -- --kind proto`)
ENTRYPOINT ["./target/release/bench_pastau"]
