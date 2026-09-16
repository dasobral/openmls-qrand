# Security Policy

## Reporting a vulnerability

Please report security issues privately to **[dasobral93@gmail.com](mailto:dasobral93@gmail.com)**.

Do not open a public GitHub issue for vulnerabilities, secret leaks, or anything that could weaken entropy provenance.

Include:

- a description of the issue and its impact
- steps to reproduce, or a proof of concept if you have one
- the crate version or git revision you tested

You should receive an acknowledgement. Fixes will be coordinated privately before any public disclosure.

## What this crate claims

`openmls-qrand` replaces the OpenMLS `OpenMlsRand` randomness source with QRNG Open API entropy.

It does **not** claim that all OpenMLS, RustCrypto, HPKE, TLS, or host-application randomness comes from the QRNG. Randomness internal to `OpenMlsCrypto` implementations (for example RustCrypto `signature_key_gen`) is out of scope.

See the [README](README.md#security-claim) for the full boundary.

## Supported versions

Only the latest commit on `main` is supported.
