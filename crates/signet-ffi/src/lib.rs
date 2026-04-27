#![allow(non_camel_case_types)]

use sig_net::*;
use std::ffi::CStr;
use std::os::raw::c_char;

pub type signet_result = i32;

// Error codes matching the C++ SDK
const SIGNET_SUCCESS: i32 = 0;
const SIGNET_ERROR_INVALID_ARG: i32 = -1;
const SIGNET_ERROR_BUFFER_FULL: i32 = -2;
const SIGNET_ERROR_CRYPTO: i32 = -3;
const SIGNET_ERROR_ENCODE: i32 = -4;
const SIGNET_ERROR_NETWORK: i32 = -5;
const SIGNET_ERROR_BUFFER_TOO_SMALL: i32 = -6;
const SIGNET_ERROR_INVALID_PACKET: i32 = -7;
const SIGNET_ERROR_INVALID_OPTION: i32 = -8;
const SIGNET_ERROR_HMAC_FAILED: i32 = -9;
const SIGNET_ERROR_PASSPHRASE_TOO_SHORT: i32 = -10;
const SIGNET_ERROR_PASSPHRASE_TOO_LONG: i32 = -11;
const SIGNET_ERROR_PASSPHRASE_INSUFFICIENT_CLASSES: i32 = -12;
const SIGNET_ERROR_PASSPHRASE_CONSECUTIVE_IDENTICAL: i32 = -13;
const SIGNET_ERROR_PASSPHRASE_CONSECUTIVE_SEQUENTIAL: i32 = -14;
const SIGNET_TEST_FAILURE: i32 = -99;

fn map_error(e: SigNetError) -> i32 {
    match e {
        SigNetError::InvalidArgument                 => SIGNET_ERROR_INVALID_ARG,
        SigNetError::BufferFull                      => SIGNET_ERROR_BUFFER_FULL,
        SigNetError::Crypto                          => SIGNET_ERROR_CRYPTO,
        SigNetError::Encode                          => SIGNET_ERROR_ENCODE,
        SigNetError::Network                         => SIGNET_ERROR_NETWORK,
        SigNetError::BufferTooSmall                  => SIGNET_ERROR_BUFFER_TOO_SMALL,
        SigNetError::InvalidPacket                   => SIGNET_ERROR_INVALID_PACKET,
        SigNetError::InvalidOption                   => SIGNET_ERROR_INVALID_OPTION,
        SigNetError::HmacFailed                      => SIGNET_ERROR_HMAC_FAILED,
        SigNetError::TestFailure                     => SIGNET_TEST_FAILURE,
        SigNetError::PassphraseTooShort              => SIGNET_ERROR_PASSPHRASE_TOO_SHORT,
        SigNetError::PassphraseTooLong               => SIGNET_ERROR_PASSPHRASE_TOO_LONG,
        SigNetError::PassphraseInsufficientClasses   => SIGNET_ERROR_PASSPHRASE_INSUFFICIENT_CLASSES,
        SigNetError::PassphraseConsecutiveIdentical  => SIGNET_ERROR_PASSPHRASE_CONSECUTIVE_IDENTICAL,
        SigNetError::PassphraseConsecutiveSequential => SIGNET_ERROR_PASSPHRASE_CONSECUTIVE_SEQUENTIAL,
        SigNetError::SessionIdOverflow               => SIGNET_ERROR_INVALID_ARG,
    }
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn signet_hmac_sha256(
    key: *const u8,
    key_len: u32,
    message: *const u8,
    msg_len: u32,
    output: *mut u8,
) -> signet_result {
    let key = std::slice::from_raw_parts(key, key_len as usize);
    let message = std::slice::from_raw_parts(message, msg_len as usize);
    let out = std::slice::from_raw_parts_mut(output, HMAC_SHA256_LENGTH);
    let mut arr = [0u8; HMAC_SHA256_LENGTH];
    match sig_net::crypto::hmac_sha256(key, message, &mut arr) {
        Ok(()) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_hkdf_expand(
    prk: *const u8,
    prk_len: u32,
    info: *const u8,
    info_len: u32,
    output: *mut u8,
) -> signet_result {
    let prk = std::slice::from_raw_parts(prk, prk_len as usize);
    let info = std::slice::from_raw_parts(info, info_len as usize);
    let out = std::slice::from_raw_parts_mut(output, DERIVED_KEY_LENGTH);
    let mut arr = [0u8; DERIVED_KEY_LENGTH];
    match sig_net::crypto::hkdf_expand(prk, info, &mut arr) {
        Ok(()) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_derive_k0_from_passphrase(
    passphrase: *const c_char,
    passphrase_len: u32,
    k0_output: *mut u8,
) -> signet_result {
    let pp = std::slice::from_raw_parts(passphrase as *const u8, passphrase_len as usize);
    let out = std::slice::from_raw_parts_mut(k0_output, K0_KEY_LENGTH);
    let mut arr = [0u8; K0_KEY_LENGTH];
    match sig_net::crypto::derive_k0_from_passphrase(pp, &mut arr) {
        Ok(()) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_derive_sender_key(
    k0: *const u8,
    sender_key: *mut u8,
) -> signet_result {
    if k0.is_null() || sender_key.is_null() {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let k0_arr = *(k0 as *const [u8; K0_KEY_LENGTH]);
    let out = std::slice::from_raw_parts_mut(sender_key, DERIVED_KEY_LENGTH);
    let mut arr = [0u8; DERIVED_KEY_LENGTH];
    match sig_net::crypto::derive_sender_key(&k0_arr, &mut arr) {
        Ok(()) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_derive_citizen_key(
    k0: *const u8,
    citizen_key: *mut u8,
) -> signet_result {
    if k0.is_null() || citizen_key.is_null() {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let k0_arr = *(k0 as *const [u8; K0_KEY_LENGTH]);
    let out = std::slice::from_raw_parts_mut(citizen_key, DERIVED_KEY_LENGTH);
    let mut arr = [0u8; DERIVED_KEY_LENGTH];
    match sig_net::crypto::derive_citizen_key(&k0_arr, &mut arr) {
        Ok(()) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_derive_manager_global_key(
    k0: *const u8,
    manager_global_key: *mut u8,
) -> signet_result {
    if k0.is_null() || manager_global_key.is_null() {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let k0_arr = *(k0 as *const [u8; K0_KEY_LENGTH]);
    let out = std::slice::from_raw_parts_mut(manager_global_key, DERIVED_KEY_LENGTH);
    let mut arr = [0u8; DERIVED_KEY_LENGTH];
    match sig_net::crypto::derive_manager_global_key(&k0_arr, &mut arr) {
        Ok(()) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_derive_manager_local_key(
    k0: *const u8,
    tuid: *const u8,
    manager_local_key: *mut u8,
) -> signet_result {
    if k0.is_null() || tuid.is_null() || manager_local_key.is_null() {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let k0_arr = *(k0 as *const [u8; K0_KEY_LENGTH]);
    let tuid_arr = *(tuid as *const [u8; TUID_LENGTH]);
    let out = std::slice::from_raw_parts_mut(manager_local_key, DERIVED_KEY_LENGTH);
    let mut arr = [0u8; DERIVED_KEY_LENGTH];
    match sig_net::crypto::derive_manager_local_key(&k0_arr, &tuid_arr, &mut arr) {
        Ok(()) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_validate_passphrase(
    passphrase: *const c_char,
    passphrase_len: u32,
) -> signet_result {
    let pp = std::slice::from_raw_parts(passphrase as *const u8, passphrase_len as usize);
    match sig_net::crypto::validate_passphrase(pp) {
        Ok(()) => SIGNET_SUCCESS,
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_generate_random_k0(k0_output: *mut u8) -> signet_result {
    let out = std::slice::from_raw_parts_mut(k0_output, K0_KEY_LENGTH);
    let mut arr = [0u8; K0_KEY_LENGTH];
    match sig_net::crypto::generate_random_k0(&mut arr) {
        Ok(()) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_generate_random_passphrase(
    passphrase_output: *mut c_char,
    buffer_size: u32,
) -> signet_result {
    if buffer_size < 11 {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let out = std::slice::from_raw_parts_mut(passphrase_output as *mut u8, buffer_size as usize);
    let mut buf = [0u8; 11];
    match sig_net::crypto::generate_random_passphrase(&mut buf) {
        Ok(()) => {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(10);
            out[..len].copy_from_slice(&buf[..len]);
            out[len] = 0;
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}

// ---------------------------------------------------------------------------
// TUID utilities
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn signet_tuid_to_hex(
    tuid: *const u8,
    hex_output: *mut c_char,
) -> signet_result {
    if tuid.is_null() || hex_output.is_null() {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let tuid_arr = *(tuid as *const [u8; TUID_LENGTH]);
    let out = std::slice::from_raw_parts_mut(hex_output as *mut u8, TUID_HEX_LENGTH + 1);
    let hex = TUID(tuid_arr).to_hex_upper();
    out[..TUID_HEX_LENGTH].copy_from_slice(&hex);
    out[TUID_HEX_LENGTH] = 0;
    SIGNET_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn signet_tuid_from_hex(
    hex_string: *const c_char,
    tuid_output: *mut u8,
) -> signet_result {
    let hex = CStr::from_ptr(hex_string).to_bytes();
    let out = std::slice::from_raw_parts_mut(tuid_output, TUID_LENGTH);
    match sig_net::crypto::tuid_from_hex_string(hex) {
        Ok(arr) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_generate_ephemeral_tuid(
    mfg_code: u16,
    tuid_output: *mut u8,
) -> signet_result {
    if tuid_output.is_null() {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let out = std::slice::from_raw_parts_mut(tuid_output, TUID_LENGTH);
    match sig_net::crypto::generate_ephemeral_tuid(mfg_code) {
        Ok(arr) => { out.copy_from_slice(&arr); SIGNET_SUCCESS }
        Err(e) => map_error(e),
    }
}

// ---------------------------------------------------------------------------
// Multicast / sequence helpers
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn signet_calculate_multicast_address(
    universe: u16,
    ip_output: *mut c_char,
    ip_output_size: u32,
) -> signet_result {
    if ip_output_size < 16 {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let octets = match sig_net::calculate_multicast_address(universe) {
        Ok(o) => o,
        Err(e) => return map_error(e),
    };
    let s = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
    let bytes = s.as_bytes();
    let out = std::slice::from_raw_parts_mut(ip_output as *mut u8, ip_output_size as usize);
    out[..bytes.len()].copy_from_slice(bytes);
    out[bytes.len()] = 0;
    SIGNET_SUCCESS
}

/// Returns the next sequence number, wrapping 0xFFFFFFFF → 1.
#[no_mangle]
pub extern "C" fn signet_increment_sequence(seq_num: u32) -> u32 {
    sig_net::increment_sequence(seq_num)
}

/// Returns 1 if the session counter should be incremented (seq_num == 0xFFFFFFFF).
#[no_mangle]
pub extern "C" fn signet_should_increment_session(seq_num: u32) -> i32 {
    if sig_net::should_increment_session(seq_num) { 1 } else { 0 }
}

// ---------------------------------------------------------------------------
// Packet builders
// Packets are written to a caller-supplied byte buffer; *out_len receives the
// number of bytes written.  Buffer must be at least MAX_UDP_PAYLOAD (1400) bytes.
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn signet_build_dmx_packet(
    out_buf: *mut u8,
    buf_size: u32,
    out_len: *mut u32,
    universe: u16,
    dmx_data: *const u8,
    slot_count: u16,
    tuid: *const u8,
    endpoint: u16,
    mfg_code: u16,
    session_id: u32,
    seq_num: u32,
    sender_key: *const u8,
    sender_key_len: u32,
    message_id: u16,
) -> signet_result {
    if out_buf.is_null() || out_len.is_null() || dmx_data.is_null() || tuid.is_null() || sender_key.is_null() {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let tuid_arr = *(tuid as *const [u8; TUID_LENGTH]);
    let data = std::slice::from_raw_parts(dmx_data, slot_count as usize);
    let key = std::slice::from_raw_parts(sender_key, sender_key_len as usize);

    let mut packet = PacketBuffer::new();
    match sig_net::send::build_dmx_packet(
        &mut packet, universe, data, slot_count, &tuid_arr,
        endpoint, mfg_code, session_id, seq_num, key, message_id, "local",
    ) {
        Ok(()) => {
            let pkt = packet.as_slice();
            if pkt.len() > buf_size as usize {
                return SIGNET_ERROR_BUFFER_FULL;
            }
            std::slice::from_raw_parts_mut(out_buf, pkt.len()).copy_from_slice(pkt);
            *out_len = pkt.len() as u32;
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_build_announce_packet(
    out_buf: *mut u8,
    buf_size: u32,
    out_len: *mut u32,
    tuid: *const u8,
    soem_code: u32,
    firmware_version_id: u32,
    firmware_version_string: *const c_char,
    protocol_version: u8,
    role_capability_bits: u8,
    endpoint_count: u16,
    change_count: u16,
    session_id: u32,
    seq_num: u32,
    citizen_key: *const u8,
    citizen_key_len: u32,
    message_id: u16,
) -> signet_result {
    if out_buf.is_null() || out_len.is_null() || tuid.is_null()
        || firmware_version_string.is_null() || citizen_key.is_null()
    {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let tuid_arr = *(tuid as *const [u8; TUID_LENGTH]);
    let fwstr = match CStr::from_ptr(firmware_version_string).to_str() {
        Ok(s) => s,
        Err(_) => return SIGNET_ERROR_INVALID_ARG,
    };
    let key = std::slice::from_raw_parts(citizen_key, citizen_key_len as usize);

    let mut packet = PacketBuffer::new();
    match sig_net::send::build_announce_packet(
        &mut packet, &tuid_arr, soem_code,
        firmware_version_id, fwstr, protocol_version, role_capability_bits,
        endpoint_count, change_count, session_id, seq_num, key, message_id, "local",
    ) {
        Ok(()) => {
            let pkt = packet.as_slice();
            if pkt.len() > buf_size as usize {
                return SIGNET_ERROR_BUFFER_FULL;
            }
            std::slice::from_raw_parts_mut(out_buf, pkt.len()).copy_from_slice(pkt);
            *out_len = pkt.len() as u32;
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_build_poll_packet(
    out_buf: *mut u8,
    buf_size: u32,
    out_len: *mut u32,
    manager_tuid: *const u8,
    soem_code: u32,
    tuid_lo: *const u8,
    tuid_hi: *const u8,
    target_endpoint: u16,
    query_level: u8,
    session_id: u32,
    seq_num: u32,
    manager_global_key: *const u8,
    manager_global_key_len: u32,
    message_id: u16,
) -> signet_result {
    if out_buf.is_null() || out_len.is_null() || manager_tuid.is_null()
        || tuid_lo.is_null() || tuid_hi.is_null() || manager_global_key.is_null()
    {
        return SIGNET_ERROR_INVALID_ARG;
    }
    let mgr_tuid = *(manager_tuid as *const [u8; TUID_LENGTH]);
    let lo = *(tuid_lo as *const [u8; TUID_LENGTH]);
    let hi = *(tuid_hi as *const [u8; TUID_LENGTH]);
    let key = std::slice::from_raw_parts(manager_global_key, manager_global_key_len as usize);

    let mut packet = PacketBuffer::new();
    match sig_net::send::build_poll_packet(
        &mut packet, &mgr_tuid, soem_code,
        &lo, &hi, target_endpoint, query_level,
        session_id, seq_num, key, message_id, "local",
    ) {
        Ok(()) => {
            let pkt = packet.as_slice();
            if pkt.len() > buf_size as usize {
                return SIGNET_ERROR_BUFFER_FULL;
            }
            std::slice::from_raw_parts_mut(out_buf, pkt.len()).copy_from_slice(pkt);
            *out_len = pkt.len() as u32;
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}
