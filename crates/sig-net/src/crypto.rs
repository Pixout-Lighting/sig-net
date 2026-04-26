use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::*;

pub fn hmac_sha256(key: &[u8], message: &[u8], output: &mut [u8; HMAC_SHA256_LENGTH]) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| SigNetError::Crypto)?;
    mac.update(message);
    output.copy_from_slice(&mac.finalize().into_bytes());
    Ok(())
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], output: &mut [u8; DERIVED_KEY_LENGTH]) -> Result<()> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(prk).map_err(|_| SigNetError::Crypto)?;
    hk.expand(info, output).map_err(|_| SigNetError::Crypto)
}

pub fn derive_k0_from_passphrase(passphrase: &[u8], k0_output: &mut [u8; K0_KEY_LENGTH]) -> Result<()> {
    if passphrase.is_empty() {
        return Err(SigNetError::InvalidArgument);
    }
    pbkdf2::pbkdf2::<Hmac<Sha256>>(passphrase, PBKDF2_SALT, PBKDF2_ITERATIONS, k0_output)
        .map_err(|_| SigNetError::Crypto)
}

pub fn derive_sender_key(k0: &[u8; K0_KEY_LENGTH], sender_key: &mut [u8; DERIVED_KEY_LENGTH]) -> Result<()> {
    hkdf_expand(k0, HKDF_INFO_SENDER, sender_key)
}

pub fn derive_citizen_key(k0: &[u8; K0_KEY_LENGTH], citizen_key: &mut [u8; DERIVED_KEY_LENGTH]) -> Result<()> {
    hkdf_expand(k0, HKDF_INFO_CITIZEN, citizen_key)
}

pub fn derive_manager_global_key(k0: &[u8; K0_KEY_LENGTH], mgr_key: &mut [u8; DERIVED_KEY_LENGTH]) -> Result<()> {
    hkdf_expand(k0, HKDF_INFO_MANAGER_GLOBAL, mgr_key)
}

pub fn derive_manager_local_key(
    k0: &[u8; K0_KEY_LENGTH],
    tuid: &[u8; TUID_LENGTH],
    mgr_local_key: &mut [u8; DERIVED_KEY_LENGTH],
) -> Result<()> {
    let hex = TUID(*tuid).to_hex();
    let mut info = [0u8; HKDF_INFO_INPUT_MAX];
    let prefix_len = HKDF_INFO_MANAGER_LOCAL_PREFIX.len();
    info[..prefix_len].copy_from_slice(HKDF_INFO_MANAGER_LOCAL_PREFIX);
    info[prefix_len..prefix_len + TUID_HEX_LENGTH].copy_from_slice(&hex);
    hkdf_expand(k0, &info[..prefix_len + TUID_HEX_LENGTH], mgr_local_key)
}

pub fn tuid_from_hex_string(hex_string: &[u8]) -> Result<[u8; TUID_LENGTH]> {
    TUID::from_hex(hex_string).map(|t| t.0)
}

pub fn generate_ephemeral_tuid(mfg_code: u16) -> Result<[u8; TUID_LENGTH]> {
    let mut random_bytes = [0u8; 4];
    getrandom::getrandom(&mut random_bytes).map_err(|_| SigNetError::Crypto)?;
    let device_id = (random_bytes[0] as u32) << 24
        | (random_bytes[1] as u32) << 16
        | (random_bytes[2] as u32) << 8
        | (random_bytes[3] as u32);
    let device_id = (device_id | 0x80000000).min(0xFFFFFFEF);
    let mut tuid = [0u8; TUID_LENGTH];
    tuid[0] = (mfg_code >> 8) as u8;
    tuid[1] = (mfg_code & 0xFF) as u8;
    tuid[2] = (device_id >> 24) as u8;
    tuid[3] = (device_id >> 16) as u8;
    tuid[4] = (device_id >> 8) as u8;
    tuid[5] = device_id as u8;
    Ok(tuid)
}

#[derive(Debug, Clone)]
pub struct PassphraseChecks {
    pub length: usize,
    pub length_ok: bool,
    pub class_count: i32,
    pub has_upper: bool,
    pub has_lower: bool,
    pub has_digit: bool,
    pub has_symbol: bool,
    pub classes_ok: bool,
    pub no_identical: bool,
    pub no_sequential: bool,
}

impl Default for PassphraseChecks {
    fn default() -> Self {
        PassphraseChecks {
            length: 0,
            length_ok: false,
            class_count: 0,
            has_upper: false,
            has_lower: false,
            has_digit: false,
            has_symbol: false,
            classes_ok: false,
            no_identical: true,
            no_sequential: true,
        }
    }
}

pub fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
    analyse_passphrase(passphrase).map(|_| ())
}

pub fn analyse_passphrase(passphrase: &[u8]) -> Result<PassphraseChecks> {
    let mut checks = PassphraseChecks::default();
    checks.length = passphrase.len();

    // Bug 3 fix: empty passphrase must return error, not Ok
    if passphrase.is_empty() {
        return Err(SigNetError::PassphraseTooShort);
    }

    checks.length_ok = checks.length >= PASSPHRASE_MIN_LENGTH && checks.length <= PASSPHRASE_MAX_LENGTH;
    if !checks.length_ok {
        return if checks.length < PASSPHRASE_MIN_LENGTH {
            Err(SigNetError::PassphraseTooShort)
        } else {
            Err(SigNetError::PassphraseTooLong)
        };
    }

    for &c in passphrase {
        if c.is_ascii_uppercase() {
            checks.has_upper = true;
        } else if c.is_ascii_lowercase() {
            checks.has_lower = true;
        } else if c.is_ascii_digit() {
            checks.has_digit = true;
        } else if PASSPHRASE_SYMBOLS.contains(&c) {
            checks.has_symbol = true;
        }
    }

    checks.class_count = [checks.has_upper, checks.has_lower, checks.has_digit, checks.has_symbol]
        .iter()
        .filter(|&&b| b)
        .count() as i32;
    checks.classes_ok = checks.class_count >= 3;

    for i in 2..passphrase.len() {
        if passphrase[i] == passphrase[i - 1] && passphrase[i] == passphrase[i - 2] {
            checks.no_identical = false;
            break;
        }
    }

    // Bug 2 fix: check both ascending and descending sequences, matching C++
    for i in 3..passphrase.len() {
        let asc = passphrase[i] == passphrase[i - 1].wrapping_add(1)
            && passphrase[i - 1] == passphrase[i - 2].wrapping_add(1)
            && passphrase[i - 2] == passphrase[i - 3].wrapping_add(1);
        let desc = passphrase[i] == passphrase[i - 1].wrapping_sub(1)
            && passphrase[i - 1] == passphrase[i - 2].wrapping_sub(1)
            && passphrase[i - 2] == passphrase[i - 3].wrapping_sub(1);
        if asc || desc {
            checks.no_sequential = false;
            break;
        }
    }

    // Bug 4 fix: error priority matches C++: identical → sequential → classes
    if !checks.no_identical {
        return Err(SigNetError::PassphraseConsecutiveIdentical);
    }
    if !checks.no_sequential {
        return Err(SigNetError::PassphraseConsecutiveSequential);
    }
    if !checks.classes_ok {
        return Err(SigNetError::PassphraseInsufficientClasses);
    }

    Ok(checks)
}

pub fn generate_random_passphrase(buf: &mut [u8; 11]) -> Result<()> {
    let sets: &[&[u8]] = &[
        PASSPHRASE_GEN_UPPERCASE,
        PASSPHRASE_GEN_LOWERCASE,
        PASSPHRASE_GEN_DIGITS,
        PASSPHRASE_GEN_SYMBOLS,
    ];

    for _ in 0..100 {
        let mut phrase = [0u8; PASSPHRASE_GENERATED_LENGTH];
        getrandom::getrandom(&mut phrase).map_err(|_| SigNetError::Crypto)?;

        for i in 0..phrase.len() {
            let idx = phrase[i] as usize;
            let set_idx = idx % 4;
            let set = sets[set_idx];
            phrase[i] = set[idx % set.len()];
        }

        if analyse_passphrase(&phrase).is_ok() {
            buf[..PASSPHRASE_GENERATED_LENGTH].copy_from_slice(&phrase);
            buf[PASSPHRASE_GENERATED_LENGTH] = 0;
            return Ok(());
        }
    }

    Err(SigNetError::Crypto)
}

pub fn generate_random_k0(k0_output: &mut [u8; K0_KEY_LENGTH]) -> Result<()> {
    getrandom::getrandom(k0_output).map_err(|_| SigNetError::Crypto)
}

pub fn build_hmac_input(
    uri_string: &str,
    options: &SigNetOptions,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    let mut pos = 0;
    let uri = uri_string.as_bytes();
    output[pos..pos + uri.len()].copy_from_slice(uri);
    pos += uri.len();
    output[pos] = options.security_mode;
    pos += 1;
    output[pos..pos + SENDER_ID_LENGTH].copy_from_slice(&options.sender_id);
    pos += SENDER_ID_LENGTH;
    output[pos..pos + 2].copy_from_slice(&options.mfg_code.to_be_bytes());
    pos += 2;
    output[pos..pos + 4].copy_from_slice(&options.session_id.to_be_bytes());
    pos += 4;
    output[pos..pos + 4].copy_from_slice(&options.seq_num.to_be_bytes());
    pos += 4;
    output[pos..pos + payload.len()].copy_from_slice(payload);
    pos += payload.len();
    Ok(pos)
}

pub fn verify_packet_hmac(
    uri_string: &str,
    options: &SigNetOptions,
    payload: &[u8],
    role_key: &[u8],
) -> Result<()> {
    use subtle::ConstantTimeEq;

    let input_len = uri_string.len() + 1 + SENDER_ID_LENGTH + 2 + 4 + 4 + payload.len();
    if input_len > HMAC_INPUT_MAX {
        return Err(SigNetError::InvalidArgument);
    }
    let mut hmac_input = [0u8; HMAC_INPUT_MAX];
    build_hmac_input(uri_string, options, payload, &mut hmac_input[..input_len])?;

    let mut computed = [0u8; HMAC_SHA256_LENGTH];
    hmac_sha256(role_key, &hmac_input[..input_len], &mut computed)?;

    if computed.ct_eq(&options.hmac).into() {
        Ok(())
    } else {
        Err(SigNetError::HmacFailed)
    }
}

pub fn compute_packet_hmac(
    uri_string: &str,
    options: &SigNetOptions,
    payload: &[u8],
    signing_key: &[u8],
) -> Result<[u8; HMAC_SHA256_LENGTH]> {
    let input_len = uri_string.len() + 1 + SENDER_ID_LENGTH + 2 + 4 + 4 + payload.len();
    if input_len > HMAC_INPUT_MAX {
        return Err(SigNetError::InvalidArgument);
    }
    let mut hmac_input = [0u8; HMAC_INPUT_MAX];
    build_hmac_input(uri_string, options, payload, &mut hmac_input[..input_len])?;
    let mut hmac = [0u8; HMAC_SHA256_LENGTH];
    hmac_sha256(signing_key, &hmac_input[..input_len], &mut hmac)?;
    Ok(hmac)
}
