# Contributing

Thanks for considering a contribution to `openmls-qrand`.

## Project fit

This crate is a small, auditable OpenMLS randomness provider. Changes should stay within that scope:

- implement `OpenMlsRand` against a QRNG Open API
- keep I/O synchronous and fail-closed
- compose with existing OpenMLS crypto and storage, rather than replacing them

Please read the [README](README.md) security claim and [`OPENMLS_QRNG_PROVIDER_IMPLEMENTATION_SPEC.md`](OPENMLS_QRNG_PROVIDER_IMPLEMENTATION_SPEC.md) before expanding behavior. In particular, do not add OS-RNG fallback, a local DRBG, entropy caching, or silent retries without an explicit design change.

## Development

You need Rust **1.91** or newer.

```bash
cargo test
cargo fmt --all
```

Live Entropy Core tests are ignored unless you point them at a real endpoint:

```bash
QRNG_LIVE_BASE_URL=http://127.0.0.1:8002 \
  cargo test --test live_ec_mls -- --ignored --nocapture
```

## Pull requests

1. Open an issue first for behavior or security-claim changes.
2. Keep diffs focused; do not mix refactors with feature work.
3. Add or update tests for any production change.
4. Restate the security claim if the randomness contract changes.
5. Mention `@dasobral` for review.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
