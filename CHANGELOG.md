# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.8.0] — Protocol spec V1.0 conformance

### Breaking Changes

- **`build_announce_packet` / `build_startup_announce_payload`** — `firmware_version_id` and `firmware_version_string` parameters removed. Per §10.2.5, the On-Boot Notification payload now contains exactly six normative TLVs (POLL_REPLY, PROTOCOL_VERSION, ROLE_CAPABILITY, ENDPOINT_COUNT, MULT_OVERRIDE, OTW_CAPABILITY); firmware version is queried separately via `TID_QUERY_FULL`. FFI `signet_build_announce_packet` signature updated accordingly.
- **Multicast Folding™ modulus** — `MULTICAST_MAX_INDEX` changed from `100` to `109` per §9.2.3 (prime modulus prevents clustering on round-number universe layouts). `calculate_multicast_address(110)` now returns `.1` instead of `.10`; deployments with >100 universes will compute different multicast groups.
- **Empty Application Payload** — CoAP payload marker (`0xFF`) is no longer emitted when the payload is empty, conforming to RFC 7252 §3 and §8.4.

### Added

- `validate_k0_entropy()` and `k0_shannon_entropy()` — §7.2.1 character-level Shannon entropy floor (≥3.0 bits/char) for auto-generated K0s. `generate_random_k0()` now retries (bounded) on entropy floor failures.
- `TID_EP_PROTOCOL = 0x090B` — §11.7.11 endpoint protocol TID for gateway scenarios.
- Regression tests: `multicast_folding_uses_prime_modulus_109`, `empty_payload_omits_coap_payload_marker`, `boot_announcement_tlv_order_matches_spec_10_2_5`, K0 Shannon entropy tests, `tid_ep_protocol_constant_present` (63 total).

### Migration Guide

1. Remove `firmware_version_id` / `firmware_version_string` arguments from `build_announce_packet` calls; if the firmware string is still needed, encode it in a separate QUERY_FULL response using `encode_tid_rt_firmware_version`.
2. Review deployments with universes ≥101: multicast group assignments shift (mod-109 vs mod-100). Re-derive group membership on both senders and receivers before rolling the update.
3. Application-level parsers that relied on a trailing `0xFF` for empty payloads must accept its absence.

---

## [0.7.0] — Protocol spec v0.19

### Breaking Changes

- **TID_PATCH → TID_UNIVERSE** — renamed everywhere (constants, TLV encoder, parser). Old name kept as `#[deprecated]` alias.
- **Ephemeral TUID → Dynamic TUID** — `generate_ephemeral_tuid` / `signet_generate_ephemeral_tuid` renamed to `generate_dynamic_tuid` / `signet_generate_dynamic_tuid`.
- **Beacon/Lost URI `/0` suffix** — `node_beacon/{TUID}/0` and `node_lost/{TUID}/0` per v0.19 spec. Packet builders and URI builders updated.
- **PATCH_ANNOUNCE_INTERVAL_SECS → UNIVERSE_ANNOUNCE_INTERVAL_SECS** — renamed without deprecated alias (0.x SemVer: backward compatibility not guaranteed).

### Added

- `SECURITY_MODE_OPEN_MODE` constant (`0x01`) for unauthenticated operation.
- `GuestKeys` struct and `export_guest_keys(k0)` — exports `(Km_global, Ks, Kc)` for Guest Manager key provisioning.
- Tests: `export_guest_keys_roundtrip` (56 total).

### Changed

- `to_hex_display()` — now uses uppercase hex characters (`ABCDEF`), matching §6.6 of the spec.

### Migration Guide

1. Replace `TID_PATCH` → `TID_UNIVERSE` (deprecated alias available).
2. Replace `generate_ephemeral_tuid` / `signet_generate_ephemeral_tuid` → `generate_dynamic_tuid` / `signet_generate_dynamic_tuid`.
3. Beacon/lost packet URIs now include trailing `/0`.
4. `PATCH_ANNOUNCE_INTERVAL_SECS` → `UNIVERSE_ANNOUNCE_INTERVAL_SECS`.
5. `to_hex_display()` now returns uppercase hex (previously lowercase).

---

## [0.6.1]

### Fixed

- Broken links in documentation.

---

## [0.6.0] — Protocol spec v0.18

### Breaking Changes

- SoemCode type alias — `mfg_code: u16` + `product_variant_id: u16` merged into a single `SoemCode = u32`. Use `soem_code(mfg, variant)` to construct, `soem_code_mfg(sc)` / `soem_code_variant(sc)` to unpack.
- `build_dmx_packet` — new `scope: &str` parameter (was hardcoded to `"local"`).
- `build_announce_packet` — new `endpoint_count: u16` parameter.
- `build_startup_announce_payload` — new `endpoint_count: u16` parameter; now encodes `TID_RT_ENDPOINT_COUNT` in the canonical §10.2.5 TLV order.
- `machine_version_id` in `TID_RT_FIRMWARE_VERSION` — type changed from `u16` to `u32` (4 bytes on the wire).
- TUID in URIs — always uppercase (`534C00000001`). `TUID::to_hex()` deprecated in favour of `to_hex_upper()` (URIs) / `to_hex_display()` (UI).
- `TID_RT_UNPROVISION` — renamed to `TID_RT_OFFBOARD`; old name kept as a `#[deprecated]` alias.

### Added

- New TIDs: `TID_PREVIEW` (0x0103), `TID_TIMECODE` (0x0202), `TID_PATCH` (0x0203), `TID_RT_MULT_OVERRIDE` (0x0606), `TID_RT_OTW_CAPABILITY` (0x060D).
- New packet builders: `build_beacon_packet`, `build_node_lost_packet`, `build_timecode_packet`, `build_preview_packet`, `build_manager_command_packet`.
- New URI builders: `build_node_beacon_uri_string`, `build_node_lost_uri_string`, `build_manager_uri_string`, `build_timecode_uri_string`, `build_preview_uri_string`.
- New TLV encoders/parsers: `encode_tid_timecode`, `encode_tid_patch`, `encode_tid_preview`, `encode_tid_rt_mult_override`, `encode_tid_rt_otw_capability`, `encode_tid_rt_reboot`, `parse_tid_timecode`, `parse_tid_patch`.
- Protocol timing constants (§16 Appendix B): `POLL_BACKOFF_MAX_MS`, `POLL_TIME_SECS`, `NODE_LOST_TIMEOUT_POLLS`, `UNIVERSE_LOST_TIMEOUT_SECS`, `OFFBOARD_LOCKOUT_SECS`, `SYNC_LOST_TIMEOUT_MS`, `IP_ROLLBACK_TIMER_SECS`, `TIMECODE_LOST_TIMEOUT_SECS`, `MANAGER_POLL_JITTER_MS`, `BEACON_MIN_INTERVAL_SECS`, `BEACON_TIMEOUT_SECS`, `NODE_PROCESSING_MAX_MS`, `ENDPOINT_SPACING_DELAY_MS`, `PATCH_ANNOUNCE_INTERVAL_SECS`, `STATUS_PUBLISH_RATE_SECS`.
- CI via GitHub Actions (test + clippy + FFI build on every push and PR).

### Added (Other)

- `SigNetError::SessionIdOverflow` variant.
- `MULTICAST_PREVIEW_IP = "239.254.255.249"` constant.
- 55 integration tests (up from 24), covering all new TIDs, packet builders, URI uppercase enforcement, firmware version, wire format, and HMAC round-trips.

---

## [0.5.2] and earlier

See [GitHub releases](https://github.com/Pixout-Lighting/sig-net/releases).
