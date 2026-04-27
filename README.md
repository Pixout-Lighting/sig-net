<p align="center">
  <br>
  <br>
  <strong style="font-size: 2em; letter-spacing: 2px">SIG-NET</strong>
  <br>
  <em>secure CoAP-based DMX512 lighting control</em>
  <br>
  <br>
</p>

<div align="center">

[![CI][ci-badge]][ci-url]
[![MIT licensed][license-badge]][license-url]

</div>

## Sig-Net Protocol Framework

Sig-Net is a secure, multicast-based protocol for **DMX512 entertainment lighting control** built on **CoAP** (RFC 7252). Provides authenticated delivery via HMAC-SHA256, key derivation via HKDF, and anti-replay protection.

This repository contains a pure Rust implementation ported from the original C++ SDK.

## Packages

| Crate | Version | Description |
|-------|---------|-------------|
| [`sig-net`](crates/sig-net/README.md) | [![crates.io][crates-badge]][crates-url] [![docs.rs][docs-badge]][docs-url] | Core library — types, crypto, CoAP, TLV, parsing, UDP |
| [`signet-ffi`](crates/signet-ffi/README.md) | — | C-compatible FFI (staticlib + cdylib + cbindgen header) |

## Examples

| | |
|---|---|
| [Rust](examples/rust/) | `cargo run -p sig-net --example <core\|crypto\|full>` |
| [C++ FFI](examples/signet-ffi/) | `make -C examples/signet-ffi run` |

## License

MIT. See [LICENSE](./LICENSE).

[crates-badge]: https://img.shields.io/crates/v/sig-net?style=flat-square
[crates-url]: https://crates.io/crates/sig-net
[docs-badge]: https://img.shields.io/docsrs/sig-net?style=flat-square
[docs-url]: https://docs.rs/sig-net
[ci-badge]: https://github.com/anomalyco/signet/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/anomalyco/signet/actions/workflows/ci.yml
[license-badge]: https://img.shields.io/badge/license-MIT-blue?style=flat-square
[license-url]: https://github.com/anomalyco/signet/blob/main/LICENSE
