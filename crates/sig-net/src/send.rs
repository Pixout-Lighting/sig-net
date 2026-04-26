use crate::*;
use crate::{coap, crypto, security, tlv};

fn compute_hmac_opt(
    uri_string: &str,
    options: &SigNetOptions,
    payload: &[u8],
    signing_key: &[u8],
) -> Result<[u8; HMAC_SHA256_LENGTH]> {
    crypto::compute_packet_hmac(uri_string, options, payload, signing_key)
}

fn write_options_2076_2204(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
    mfg_code: u16,
    session_id: u32,
    seq_num: u32,
) -> Result<SigNetOptions> {
    let mut options = SigNetOptions::default();
    options.security_mode = SECURITY_MODE_HMAC_SHA256;
    security::build_sender_id(tuid, endpoint, &mut options.sender_id);
    options.mfg_code = mfg_code;
    options.session_id = session_id;
    options.seq_num = seq_num;
    security::build_signet_options_without_hmac(buffer, &options, COAP_OPTION_URI_PATH)?;
    Ok(options)
}

fn write_uri_path_segments(buffer: &mut PacketBuffer, segments: &[&str]) -> Result<()> {
    let mut prev: u16 = 0;
    for &seg in segments {
        coap::encode_coap_option(buffer, COAP_OPTION_URI_PATH, prev, seg.as_bytes())?;
        prev = COAP_OPTION_URI_PATH;
    }
    Ok(())
}

pub fn build_dmx_packet(
    buffer: &mut PacketBuffer,
    universe: u16,
    dmx_data: &[u8],
    slot_count: u16,
    tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
    mfg_code: u16,
    session_id: u32,
    seq_num: u32,
    sender_key: &[u8],
    message_id: u16,
) -> Result<()> {
    if slot_count == 0 || slot_count > MAX_DMX_SLOTS || dmx_data.len() < slot_count as usize {
        return Err(SigNetError::InvalidArgument);
    }
    let slots = &dmx_data[..slot_count as usize];

    buffer.reset();
    coap::build_coap_header(buffer, message_id)?;
    coap::build_uri_path_options(buffer, universe)?;

    let options = write_options_2076_2204(buffer, tuid, endpoint, mfg_code, session_id, seq_num)?;

    // Bug 1 fix: build TLV payload first so HMAC covers the full TLV (type + length + data),
    // matching the C++ FinalizePacketWithHMACAndPayload behaviour.
    let mut payload_buf = PacketBuffer::new();
    tlv::encode_tid_level(&mut payload_buf, slots)?;

    let mut uri_buf = [0u8; URI_STRING_MIN_BUFFER as usize];
    let uri_len = coap::build_uri_string(universe, &mut uri_buf)?;
    let uri_string = core::str::from_utf8(&uri_buf[..uri_len])
        .map_err(|_| SigNetError::Encode)?;

    let hmac = compute_hmac_opt(uri_string, &options, payload_buf.as_slice(), sender_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    buffer.write_byte(COAP_PAYLOAD_MARKER)?;
    buffer.write_bytes(payload_buf.as_slice())
}

pub fn build_announce_packet(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    product_variant_id: u16,
    firmware_version_id: u16,
    firmware_version_string: &str,
    protocol_version: u8,
    role_capability_bits: u8,
    change_count: u16,
    session_id: u32,
    seq_num: u32,
    citizen_key: &[u8],
    message_id: u16,
) -> Result<()> {
    buffer.reset();

    coap::build_coap_header(buffer, message_id)?;

    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_SCOPE_DEFAULT, SIGNET_URI_NODE,
    ];
    write_uri_path_segments(buffer, &segments)?;

    let hex = TUID(*tuid).to_hex();
    let hex_str = core::str::from_utf8(&hex).map_err(|_| SigNetError::Encode)?;
    let mut prev: u16 = COAP_OPTION_URI_PATH;
    coap::encode_coap_option(buffer, COAP_OPTION_URI_PATH, prev, hex_str.as_bytes())?;
    prev = COAP_OPTION_URI_PATH;
    coap::encode_coap_option(buffer, COAP_OPTION_URI_PATH, prev, b"0")?;

    let options = write_options_2076_2204(buffer, tuid, 0, mfg_code, session_id, seq_num)?;

    // Build payload in a temp buffer for HMAC calculation
    let mut payload_buf = PacketBuffer::new();
    tlv::build_startup_announce_payload(
        &mut payload_buf, tuid, mfg_code, product_variant_id,
        firmware_version_id, firmware_version_string,
        protocol_version, role_capability_bits, change_count,
    )?;

    let mut uri_buf = [0u8; URI_STRING_MIN_BUFFER as usize];
    let uri_len = coap::build_node_uri_string(tuid, 0, &mut uri_buf)?;
    let uri_string = core::str::from_utf8(&uri_buf[..uri_len])
        .map_err(|_| SigNetError::Encode)?;

    let hmac = compute_hmac_opt(uri_string, &options, payload_buf.as_slice(), citizen_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    buffer.write_byte(COAP_PAYLOAD_MARKER)?;
    buffer.write_bytes(payload_buf.as_slice())
}

pub fn build_poll_packet(
    buffer: &mut PacketBuffer,
    manager_tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    product_variant_id: u16,
    tuid_lo: &[u8; TUID_LENGTH],
    tuid_hi: &[u8; TUID_LENGTH],
    target_endpoint: u16,
    query_level: u8,
    session_id: u32,
    seq_num: u32,
    manager_global_key: &[u8],
    message_id: u16,
) -> Result<()> {
    buffer.reset();

    coap::build_coap_header(buffer, message_id)?;

    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_SCOPE_DEFAULT, SIGNET_URI_POLL,
    ];
    write_uri_path_segments(buffer, &segments)?;

    let options = write_options_2076_2204(buffer, manager_tuid, 0, mfg_code, session_id, seq_num)?;

    // Build payload in temp buffer
    let mut payload_buf = PacketBuffer::new();
    tlv::encode_tid_poll(
        &mut payload_buf, manager_tuid, mfg_code, product_variant_id,
        tuid_lo, tuid_hi, target_endpoint, query_level,
    )?;

    let poll_uri = format!(
        "/{}/{}/{}/{}",
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_SCOPE_DEFAULT, SIGNET_URI_POLL
    );

    let hmac = compute_hmac_opt(&poll_uri, &options, payload_buf.as_slice(), manager_global_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    buffer.write_byte(COAP_PAYLOAD_MARKER)?;
    buffer.write_bytes(payload_buf.as_slice())
}
