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

[![crates.io][crates-badge]][crates-url]
[![docs.rs][docs-badge]][docs-url]
[![MIT licensed][license-badge]][license-url]
[![Rust 1.75+][rust-badge]][rust-url]

</div>

## Sig-Net Protocol Framework

_sĭg nĕt_

Sig-Net is a secure, multicast-based protocol for **DMX512 entertainment lighting control** built on **CoAP** (RFC 7252). It provides authenticated packet delivery via HMAC-SHA256, key derivation via HKDF, and anti-replay protection — all in a lightweight UDP multicast package.

This is a **pure Rust** implementation of the Sig-Net Protocol Framework specification, ported from the original C++ SDK with zero `unsafe` code.

## Repository Packages

| Package | crates.io | Docs | Description |
|---------|-----------|------|-------------|
| `sig-net` (this crate) | [![crates.io][crates-badge]][crates-url] | [![docs.rs][docs-badge]][docs-url] | Core library — types, crypto, CoAP, TLV, parsing, UDP |
| [`signet-ffi`](../signet-ffi/README.md) | — | — | C-compatible FFI bindings (staticlib + cdylib + cbindgen header) |

## Quick Start

```toml
[dependencies]
sig-net = "0.5"
```

**Build and send a DMX level packet:**

```rust
use sig_net::*;

let mut k0 = [0u8; 32];
crypto::derive_k0_from_passphrase(b"Ge2p$E$4*A", &mut k0)?;

let mut sender_key = [0u8; 32];
crypto::derive_sender_key(&k0, &mut sender_key)?;

let tuid = TUID::from_hex(b"534C00000001")?;
let dmx: Vec<u8> = (0..512).map(|i| (i * 4) as u8).collect();

let mut buf = PacketBuffer::new();
send::build_dmx_packet(&mut buf, 1, &dmx, &tuid.0, 0, 0x0000, 1, 1, &sender_key, 1)?;
```

## Feature Flags

```toml
[dependencies]
sig-net = { version = "0.5", default-features = false }       # core types (zero deps)
sig-net = { version = "0.5", features = ["crypto"] }          # + HMAC/HKDF/PBKDF2/passphrase
sig-net = { version = "0.5", features = ["crypto", "net"] }   # + UDP multicast (default)
```

## API Overview

### Core Types

```rust
let header = CoAPHeader::new(42);
let mut buf = PacketBuffer::new();
let tuid = TUID::from_hex(b"534C00000001")?;
let addr = calculate_multicast_address(1)?;
```

### Cryptography (`sig_net::crypto`)

```rust
crypto::hmac_sha256(key, data, &mut hmac)?;
crypto::hkdf_expand(prk, info, &mut okm)?;
crypto::derive_k0_from_passphrase(pw, &mut k0)?;
crypto::derive_sender_key(&k0, &mut ks)?;
crypto::validate_passphrase(b"Ge2p$E$4*A")?;
crypto::verify_packet_hmac(uri, &options, payload, &key)?;
```

### Protocol Building

```rust
coap::build_coap_header(&mut buf, message_id)?;
tlv::encode_tid_level(&mut buf, &dmx_data)?;
send::build_dmx_packet(&mut buf, 1, &dmx, &tuid, 0, ...)?;
send::build_announce_packet(&mut buf, &tuid, ...)?;
send::build_poll_packet(&mut buf, &mgr_tuid, ...)?;
```

### Protocol Parsing

```rust
let mut reader = parse::PacketReader::new(packet, packet_len);
let header = reader.parse_coap_header()?;
let options = reader.parse_signet_options()?;
let tlv = reader.parse_tlv_block()?;
let slots = parse::parse_tid_level(&tlv, &mut dmx)?;
```

### UDP Multicast

```rust
let socket = net::UdpMulticastSocket::bind(5683)?;
socket.join_multicast_group(Ipv4Addr::new(239, 254, 0, 1), None)?;
socket.send_multicast(packet, 1)?;
let (n, src) = socket.recv_from(&mut rx_buf)?;
```

### C / C++ FFI

See [`signet-ffi`](../signet-ffi/README.md).

```cpp
#include "signet.h"

uint8_t k0[32];
signet_derive_k0_from_passphrase("Ge2p$E$4*A", 10, k0);

uint8_t sender_key[32];
signet_derive_sender_key(k0, sender_key);
```

## Examples

| Example | Location | Run |
|---------|----------|------|
| Core types | [`examples/rust/core.rs`](../../examples/rust/core.rs) | `cargo run -p sig-net --example core` |
| Cryptography | [`examples/rust/crypto.rs`](../../examples/rust/crypto.rs) | `cargo run -p sig-net --example crypto` |
| Full protocol | [`examples/rust/full.rs`](../../examples/rust/full.rs) | `cargo run -p sig-net --example full` |
| C++ FFI demo | [`examples/signet-ffi/ffi-demo.cpp`](../../examples/signet-ffi/ffi-demo.cpp) | `make -C examples/signet-ffi run` |

## Test Vectors

| Test | Status | Details |
|------|--------|---------|
| [RFC 4231 TC1](https://datatracker.ietf.org/doc/html/rfc4231#section-4) | ✅ | Key=20×0x0B, Data="Hi There", HMAC=`B0344C61...` |
| [RFC 4231 TC2](https://datatracker.ietf.org/doc/html/rfc4231#section-4) | ✅ | Key="Jefe", Data="what do ya want...", HMAC=`5BDCC146...` |
| [PBKDF2](https://datatracker.ietf.org/doc/html/rfc8018) K0 | ✅ | 100k iterations, "Ge2p$E$4*A" → K0=`52FCC2E7...` |

## Crate Structure

```
crates/
├── sig-net/          ← main library
│   ├── src/
│   │   ├── constants  protocol constants (TIDs, option numbers, crypto params)
│   │   ├── types      CoAPHeader, PacketBuffer, TUID, SigNetOptions
│   │   ├── crypto     HMAC-SHA256, HKDF, PBKDF2, key derivation, passphrase
│   │   ├── coap       CoAP header/option encoding, URI building
│   │   ├── tlv        TLV payload encoding
│   │   ├── security   SigNet custom options, HMAC input/output
│   │   ├── send       DMX packet, announce, poll packet builders
│   │   ├── parse      PacketReader, CoAP/TLV parsing, HMAC verification
│   │   └── net        UDP multicast (socket2)
│   └── tests/
│       └── integration.rs  24 integration tests
└── signet-ffi/        ← C-compatible FFI (see [README](../signet-ffi/README.md))
examples/
├── rust/              ← Rust examples (core, crypto, full)
└── signet-ffi/        ← C++ FFI demo (ffi-demo.cpp + Makefile)
```

## Safety

**Zero `unsafe` blocks** in the entire `sig-net` library:
- CoAP header uses manual bit-shifting instead of `#[repr(packed)]`
- Network I/O uses the `socket2` crate (safe abstraction over Winsock/BSD sockets)
- Constant-time HMAC comparison uses the `subtle` crate

## License

Sig-Net is free and open-source software licensed under the [MIT License](./LICENSE).

[crates-badge]: https://img.shields.io/crates/v/sig-net?style=flat-square
[crates-url]: https://crates.io/crates/sig-net
[docs-badge]: https://img.shields.io/docsrs/sig-net?style=flat-square
[docs-url]: https://docs.rs/sig-net
[license-badge]: https://img.shields.io/badge/license-MIT-blue?style=flat-square
[license-url]: https://github.com/anomalyco/signet/blob/main/LICENSE
[rust-badge]: https://img.shields.io/badge/rust-1.75%2B-blue?style=flat-square
[rust-url]: https://www.rust-lang.org
