# openmls-qrng-provider

A small, reusable Rust library that supplies QRNG-backed randomness to OpenMLS.

This crate is **not** agent-trust-specific. Any OpenMLS application that can reach a QRNG Open API endpoint can use it.

## Status

This repository currently contains the implementation specification. Implementation proceeds on `feat/initial-qrng-provider`.

See [OPENMLS_QRNG_PROVIDER_IMPLEMENTATION_SPEC.md](OPENMLS_QRNG_PROVIDER_IMPLEMENTATION_SPEC.md) for the binding design.

## Security claim

The library replaces the OpenMLS `OpenMlsRand` randomness source with entropy obtained through QRNG Open API.

It does **not** claim that all randomness used by OpenMLS, RustCrypto, HPKE, signatures, TLS, or the host application comes from the QRNG.

## License

MIT
