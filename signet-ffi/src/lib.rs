#![allow(non_camel_case_types)]

use sig_net::*;
use std::ffi::CStr;
use std::os::raw::c_char;

pub type signet_result = i32;

const SIGNET_SUCCESS: i32 = 0;
const SIGNET_ERROR_INVALID_ARG: i32 = -1;
const SIGNET_ERROR_CRYPTO: i32 = -3;
const SIGNET_ERROR_PASSPHRASE_TOO_SHORT: i32 = -10;
const SIGNET_ERROR_PASSPHRASE_TOO_LONG: i32 = -11;
const SIGNET_ERROR_PASSPHRASE_INSUFFICIENT_CLASSES: i32 = -12;
const SIGNET_ERROR_PASSPHRASE_CONSECUTIVE_IDENTICAL: i32 = -13;
const SIGNET_ERROR_PASSPHRASE_CONSECUTIVE_SEQUENTIAL: i32 = -14;

fn map_error(e: SigNetError) -> i32 {
    match e {
        SigNetError::InvalidArgument => SIGNET_ERROR_INVALID_ARG,
        SigNetError::Crypto => SIGNET_ERROR_CRYPTO,
        SigNetError::PassphraseTooShort => SIGNET_ERROR_PASSPHRASE_TOO_SHORT,
        SigNetError::PassphraseTooLong => SIGNET_ERROR_PASSPHRASE_TOO_LONG,
        SigNetError::PassphraseInsufficientClasses => SIGNET_ERROR_PASSPHRASE_INSUFFICIENT_CLASSES,
        SigNetError::PassphraseConsecutiveIdentical => SIGNET_ERROR_PASSPHRASE_CONSECUTIVE_IDENTICAL,
        SigNetError::PassphraseConsecutiveSequential => SIGNET_ERROR_PASSPHRASE_CONSECUTIVE_SEQUENTIAL,
        _ => SIGNET_ERROR_INVALID_ARG,
    }
}

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
        Ok(()) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
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
        Ok(()) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
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
        Ok(()) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_derive_sender_key(
    k0: *const u8,
    sender_key: *mut u8,
) -> signet_result {
    let k0_arr = *(k0 as *const [u8; K0_KEY_LENGTH]);
    let out = std::slice::from_raw_parts_mut(sender_key, DERIVED_KEY_LENGTH);
    let mut arr = [0u8; DERIVED_KEY_LENGTH];
    match sig_net::crypto::derive_sender_key(&k0_arr, &mut arr) {
        Ok(()) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_derive_citizen_key(
    k0: *const u8,
    citizen_key: *mut u8,
) -> signet_result {
    let k0_arr = *(k0 as *const [u8; K0_KEY_LENGTH]);
    let out = std::slice::from_raw_parts_mut(citizen_key, DERIVED_KEY_LENGTH);
    let mut arr = [0u8; DERIVED_KEY_LENGTH];
    match sig_net::crypto::derive_citizen_key(&k0_arr, &mut arr) {
        Ok(()) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_derive_manager_global_key(
    k0: *const u8,
    manager_global_key: *mut u8,
) -> signet_result {
    let k0_arr = *(k0 as *const [u8; K0_KEY_LENGTH]);
    let out = std::slice::from_raw_parts_mut(manager_global_key, DERIVED_KEY_LENGTH);
    let mut arr = [0u8; DERIVED_KEY_LENGTH];
    match sig_net::crypto::derive_manager_global_key(&k0_arr, &mut arr) {
        Ok(()) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
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
        Ok(()) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
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

#[no_mangle]
pub unsafe extern "C" fn signet_tuid_to_hex(
    tuid: *const u8,
    hex_output: *mut c_char,
) -> signet_result {
    let tuid_arr = *(tuid as *const [u8; TUID_LENGTH]);
    let out = std::slice::from_raw_parts_mut(hex_output as *mut u8, TUID_HEX_LENGTH + 1);
    let hex = TUID(tuid_arr).to_hex();
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
        Ok(arr) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signet_generate_ephemeral_tuid(
    mfg_code: u16,
    tuid_output: *mut u8,
) -> signet_result {
    let out = std::slice::from_raw_parts_mut(tuid_output, TUID_LENGTH);
    match sig_net::crypto::generate_ephemeral_tuid(mfg_code) {
        Ok(arr) => {
            out.copy_from_slice(&arr);
            SIGNET_SUCCESS
        }
        Err(e) => map_error(e),
    }
}
