# PAS-TA-U (Rust) + Benchmark Harness

This repo contains a **self-contained PAS-TA-U implementation** (client + identity servers) and a
single benchmark binary that reports:

- **Client protocol time** (`--kind proto`) – setup, registration, authentication, verify
- **Server protocol time** (`--kind sp`) – store, db_get, respond
- **Crypto primitive microbenches** (`--kind prim`) – TOPRF, AEAD, TTG (threshold token generator)
- **Network-only simulation** (`--kind net`) – LAN/WAN model (latency + jitter + bandwidth)
- **End-to-end simulation** (`--kind full`) – client CPU + simulated net + injected server p50

The crypto core is reused from the uploaded primitives (Blake3 + XChaCha20-Poly1305 + Ristretto TOPRF).

## Layout

```
src/
  crypto_core.rs          # core primitives (TOPRF + XChaCha AEAD)
  crypto_pastau.rs        # PAS-TA-U glue + TTG (threshold BLS signatures)
  protocols/pastau.rs     # PAS-TA-U protocol implementation (includes PasswordUpdate)
  bin/bench_pastau.rs     # benchmark driver
```

## Build

```bash
cargo build --release
```

## Run benchmarks

Default runs everything (proto + prim + sp + net + full) for `nsp=20,40,60` and `tsp=ceil(50% of nsp)`:

```bash
cargo run --release --bin bench_pastau
```

Client protocol only:

```bash
cargo run --release --bin bench_pastau -- --kind proto
```

Primitives only:

```bash
cargo run --release --bin bench_pastau -- --kind prim
```

Network simulation only (LAN+WAN):

```bash
cargo run --release --bin bench_pastau -- --kind net --net all
```

Full end-to-end on WAN, include RNG cost in timed sections:

```bash
cargo run --release --bin bench_pastau -- --kind full --net wan --rng-in-timed
```

Change the server counts / thresholds:

```bash
cargo run --release --bin bench_pastau -- --nsp 50,100 --tsp 10,20
# or derive tsp from percentages
cargo run --release --bin bench_pastau -- --nsp 50,100 --tsp-pct 20,40,60
```

Output file:

```bash
cargo run --release --bin bench_pastau -- --out results.txt
```

## Notes on TTG

PAS-TA-U needs a publicly verifiable, t-out-of-n combinable token. In this benchmark code,
`TTG` is implemented as **threshold BLS signatures over BLS12-381**:

- `TTG.PartEval(sk_i, m)` = partial signature in G1
- `TTG.Combine(...)` = Lagrange interpolation in the exponent
- `TTG.Verify(vk, m, sig)` = pairing check

For benchmarking simplicity, the “hash to G1” is a deterministic map based on Blake3-expanded
wide bytes -> BLS scalar -> scalar-mul of the G1 generator.

## Output columns

Each line is:

```
scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns
```

Times are in **nanoseconds**.
