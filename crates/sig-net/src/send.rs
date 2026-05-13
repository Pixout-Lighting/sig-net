#![allow(clippy::too_many_arguments)]
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
    let mut options = SigNetOptions {
        security_mode: SECURITY_MODE_HMAC_SHA256,
        ..Default::default()
    };
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

/// §8.4 / RFC 7252 §3: the 0xFF payload marker shall be omitted when the
/// Application Payload is empty.
fn write_packet_payload(buffer: &mut PacketBuffer, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    buffer.write_byte(COAP_PAYLOAD_MARKER)?;
    buffer.write_bytes(payload)
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
    scope: &str,
) -> Result<()> {
    if slot_count == 0 || slot_count > MAX_DMX_SLOTS || dmx_data.len() < slot_count as usize {
        return Err(SigNetError::InvalidArgument);
    }
    let slots = &dmx_data[..slot_count as usize];

    buffer.reset();
    coap::build_coap_header(buffer, message_id)?;
    coap::build_uri_path_options(buffer, universe, scope)?;

    let options = write_options_2076_2204(buffer, tuid, endpoint, mfg_code, session_id, seq_num)?;

    // Bug 1 fix: build TLV payload first so HMAC covers the full TLV (type + length + data),
    // matching the C++ FinalizePacketWithHMACAndPayload behaviour.
    let mut payload_buf = PacketBuffer::new();
    tlv::encode_tid_level(&mut payload_buf, slots)?;

    let mut uri_buf = [0u8; URI_STRING_MIN_BUFFER as usize];
    let uri_len = coap::build_uri_string(universe, scope, &mut uri_buf)?;
    let uri_string = core::str::from_utf8(&uri_buf[..uri_len])
        .map_err(|_| SigNetError::Encode)?;

    let hmac = compute_hmac_opt(uri_string, &options, payload_buf.as_slice(), sender_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    write_packet_payload(buffer, payload_buf.as_slice())
}

/// Build On-Boot Notification packet (§10.2.5).
///
/// Note: per §10.2.5 the payload contains exactly 6 normative TLVs in fixed
/// order — firmware version, model name, etc. are queried separately
/// (TID_QUERY_FULL).
pub fn build_announce_packet(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    soem_code: SoemCode,
    protocol_version: u8,
    role_capability_bits: u8,
    endpoint_count: u16,
    change_count: u16,
    session_id: u32,
    seq_num: u32,
    citizen_key: &[u8],
    message_id: u16,
    scope: &str,
) -> Result<()> {
    buffer.reset();

    coap::build_coap_header(buffer, message_id)?;

    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, scope, SIGNET_URI_NODE,
    ];
    write_uri_path_segments(buffer, &segments)?;

    let hex = TUID(*tuid).to_hex_upper();
    let hex_str = core::str::from_utf8(&hex).map_err(|_| SigNetError::Encode)?;
    let mut prev: u16 = COAP_OPTION_URI_PATH;
    coap::encode_coap_option(buffer, COAP_OPTION_URI_PATH, prev, hex_str.as_bytes())?;
    prev = COAP_OPTION_URI_PATH;
    coap::encode_coap_option(buffer, COAP_OPTION_URI_PATH, prev, b"0")?;

    let mfg_code = soem_code_mfg(soem_code);
    let options = write_options_2076_2204(buffer, tuid, 0, mfg_code, session_id, seq_num)?;

    // Build payload in a temp buffer for HMAC calculation
    let mut payload_buf = PacketBuffer::new();
    tlv::build_startup_announce_payload(
        &mut payload_buf, tuid, soem_code,
        protocol_version, role_capability_bits, endpoint_count, change_count,
        0,  // mult_override_state: default
        None,  // otw_capability: not supported
    )?;

    let mut uri_buf = [0u8; URI_STRING_MIN_BUFFER as usize];
    let uri_len = coap::build_node_uri_string(tuid, 0, scope, &mut uri_buf)?;
    let uri_string = core::str::from_utf8(&uri_buf[..uri_len])
        .map_err(|_| SigNetError::Encode)?;

    let hmac = compute_hmac_opt(uri_string, &options, payload_buf.as_slice(), citizen_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    write_packet_payload(buffer, payload_buf.as_slice())
}

pub fn build_poll_packet(
    buffer: &mut PacketBuffer,
    manager_tuid: &[u8; TUID_LENGTH],
    soem_code: SoemCode,
    tuid_lo: &[u8; TUID_LENGTH],
    tuid_hi: &[u8; TUID_LENGTH],
    target_endpoint: u16,
    query_level: u8,
    session_id: u32,
    seq_num: u32,
    manager_global_key: &[u8],
    message_id: u16,
    scope: &str,
) -> Result<()> {
    buffer.reset();

    coap::build_coap_header(buffer, message_id)?;

    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, scope, SIGNET_URI_POLL,
    ];
    write_uri_path_segments(buffer, &segments)?;

    let mfg_code = soem_code_mfg(soem_code);
    let options = write_options_2076_2204(buffer, manager_tuid, 0, mfg_code, session_id, seq_num)?;

    // Build payload in temp buffer
    let mut payload_buf = PacketBuffer::new();
    tlv::encode_tid_poll(
        &mut payload_buf, manager_tuid,
        soem_code,
        tuid_lo, tuid_hi, target_endpoint, query_level,
    )?;

    let poll_uri = format!(
        "/{}/{}/{}/{}",
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, scope, SIGNET_URI_POLL
    );

    let hmac = compute_hmac_opt(&poll_uri, &options, payload_buf.as_slice(), manager_global_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    write_packet_payload(buffer, payload_buf.as_slice())
}

/// Build timecode packet (§11.2.5).
/// URI: /sig-net/v1/<scope>/timecode/{stream} → <mult_time> = 239.254.255.250
pub fn build_timecode_packet(
    buffer: &mut PacketBuffer,
    stream: u8,
    hours: u8,
    minutes: u8,
    seconds: u8,
    frames: u8,
    tc_type: u8,
    tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
    mfg_code: u16,
    session_id: u32,
    seq_num: u32,
    sender_key: &[u8],
    message_id: u16,
    scope: &str,
) -> Result<()> {
    buffer.reset();
    coap::build_coap_header(buffer, message_id)?;

    let stream_str = stream.to_string();
    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, scope, "timecode", &stream_str,
    ];
    write_uri_path_segments(buffer, &segments)?;

    let options = write_options_2076_2204(buffer, tuid, endpoint, mfg_code, session_id, seq_num)?;

    let mut payload_buf = PacketBuffer::new();
    tlv::encode_tid_timecode(&mut payload_buf, hours, minutes, seconds, frames, tc_type)?;

    let mut uri_buf = [0u8; URI_STRING_MIN_BUFFER as usize];
    let uri_len = coap::build_timecode_uri_string(stream, scope, &mut uri_buf)?;
    let uri_string = core::str::from_utf8(&uri_buf[..uri_len])
        .map_err(|_| SigNetError::Encode)?;

    let hmac = compute_hmac_opt(uri_string, &options, payload_buf.as_slice(), sender_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    write_packet_payload(buffer, payload_buf.as_slice())
}

/// Build preview packet (§11.2.3).
/// URI: /sig-net/v1/<scope>/preview/{universe} → <mult_preview> = 239.254.255.249
pub fn build_preview_packet(
    buffer: &mut PacketBuffer,
    universe: u16,
    dmx_data: &[u8],
    tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
    mfg_code: u16,
    session_id: u32,
    seq_num: u32,
    sender_key: &[u8],
    message_id: u16,
    scope: &str,
) -> Result<()> {
    if dmx_data.is_empty() || dmx_data.len() > MAX_DMX_SLOTS as usize {
        return Err(SigNetError::InvalidArgument);
    }

    buffer.reset();
    coap::build_coap_header(buffer, message_id)?;

    let universe_str = universe.to_string();
    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, scope, "preview", &universe_str,
    ];
    write_uri_path_segments(buffer, &segments)?;

    let options = write_options_2076_2204(buffer, tuid, endpoint, mfg_code, session_id, seq_num)?;

    let mut payload_buf = PacketBuffer::new();
    tlv::encode_tid_preview(&mut payload_buf, dmx_data)?;

    let mut uri_buf = [0u8; URI_STRING_MIN_BUFFER as usize];
    let uri_len = coap::build_preview_uri_string(universe, scope, &mut uri_buf)?;
    let uri_string = core::str::from_utf8(&uri_buf[..uri_len])
        .map_err(|_| SigNetError::Encode)?;

    let hmac = compute_hmac_opt(uri_string, &options, payload_buf.as_slice(), sender_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    write_packet_payload(buffer, payload_buf.as_slice())
}

/// Build beacon packet (§10.2.1). Security-Mode = 0xFF (unprovisioned), HMAC = zeros.
/// URI: /sig-net/v1/local/node_beacon/{TUID}/0 → <mult_node_beacon> = 239.254.255.255
pub fn build_beacon_packet(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    soem_code: SoemCode,
    device_label: &str,
    endpoint_count: u16,
    otw_capability: Option<(u16, u8)>,
    message_id: u16,
) -> Result<()> {
    buffer.reset();
    coap::build_coap_header(buffer, message_id)?;

    let hex = TUID(*tuid).to_hex_upper();
    let hex_str = core::str::from_utf8(&hex).map_err(|_| SigNetError::Encode)?;
    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, "local", "node_beacon", hex_str, "0",
    ];
    write_uri_path_segments(buffer, &segments)?;

    // Security-Mode 0xFF: unprovisioned, only option 2076 + HMAC 2236
    coap::encode_coap_option(buffer, SIGNET_OPTION_SECURITY_MODE, COAP_OPTION_URI_PATH, &[SECURITY_MODE_UNPROVISIONED])?;

    let zero_hmac = [0u8; HMAC_SHA256_LENGTH];
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SECURITY_MODE, &zero_hmac)?;

    // Payload: POLL_REPLY(change_count=0), DEVICE_LABEL, ENDPOINT_COUNT, OTW_CAPABILITY(optional)
    let mut payload_buf = PacketBuffer::new();
    tlv::encode_tid_poll_reply(&mut payload_buf, tuid, soem_code, 0)?;

    let dl = device_label.as_bytes();
    let label_tlv = TLVBlock { type_id: TID_RT_DEVICE_LABEL, value: dl };
    tlv::encode_tlv(&mut payload_buf, &label_tlv)?;

    let ec_bytes = endpoint_count.to_be_bytes();
    let ec_tlv = TLVBlock { type_id: TID_RT_ENDPOINT_COUNT, value: &ec_bytes };
    tlv::encode_tlv(&mut payload_buf, &ec_tlv)?;

    if let Some((port, protocols)) = otw_capability {
        tlv::encode_tid_rt_otw_capability(&mut payload_buf, port, protocols)?;
    }

    write_packet_payload(buffer, payload_buf.as_slice())
}

/// Build node_lost packet (§10.2.6).
/// URI: /sig-net/v1/<scope>/node_lost/{TUID}/0 → <mult_node_lost> = 239.254.255.254
pub fn build_node_lost_packet(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    soem_code: SoemCode,
    endpoint_count: u16,
    protocol_version: u8,
    role_capability_bits: u8,
    mult_override_state: u8,
    otw_capability: Option<(u16, u8)>,
    session_id: u32,
    seq_num: u32,
    citizen_key: &[u8],
    message_id: u16,
    scope: &str,
) -> Result<()> {
    buffer.reset();
    coap::build_coap_header(buffer, message_id)?;

    let hex = TUID(*tuid).to_hex_upper();
    let hex_str = core::str::from_utf8(&hex).map_err(|_| SigNetError::Encode)?;
    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, scope, "node_lost", hex_str, "0",
    ];
    write_uri_path_segments(buffer, &segments)?;

    let mfg_code = soem_code_mfg(soem_code);
    let options = write_options_2076_2204(buffer, tuid, 0, mfg_code, session_id, seq_num)?;

    let mut payload_buf = PacketBuffer::new();
    // Canonical order (§10.2.6):
    // 1. TID_POLL_REPLY
    tlv::encode_tid_poll_reply(&mut payload_buf, tuid, soem_code, 0)?;
    // 2. TID_RT_PROTOCOL_VERSION
    tlv::encode_tid_rt_protocol_version(&mut payload_buf, protocol_version)?;
    // 3. TID_RT_ROLE_CAPABILITY
    tlv::encode_tid_rt_role_capability(&mut payload_buf, role_capability_bits)?;
    // 4. TID_RT_ENDPOINT_COUNT
    let ec_bytes = endpoint_count.to_be_bytes();
    let ec_tlv = TLVBlock { type_id: TID_RT_ENDPOINT_COUNT, value: &ec_bytes };
    tlv::encode_tlv(&mut payload_buf, &ec_tlv)?;
    // 5. TID_RT_MULT_OVERRIDE
    tlv::encode_tid_rt_mult_override(&mut payload_buf, mult_override_state)?;
    // 6. TID_RT_OTW_CAPABILITY (optional)
    if let Some((port, protocols)) = otw_capability {
        tlv::encode_tid_rt_otw_capability(&mut payload_buf, port, protocols)?;
    }

    let mut uri_buf = [0u8; URI_STRING_MIN_BUFFER as usize];
    let uri_len = coap::build_node_lost_uri_string(tuid, scope, &mut uri_buf)?;
    let uri_string = core::str::from_utf8(&uri_buf[..uri_len])
        .map_err(|_| SigNetError::Encode)?;

    let hmac = compute_hmac_opt(uri_string, &options, payload_buf.as_slice(), citizen_key)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    write_packet_payload(buffer, payload_buf.as_slice())
}

/// Build manager command packet (§11.3).
/// URI: /sig-net/v1/<scope>/manager/{target_TUID}/{endpoint} → <mult_manager_send> = 239.254.255.251
pub fn build_manager_command_packet(
    buffer: &mut PacketBuffer,
    target_tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
    tlv_payload: &[u8],
    manager_tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    session_id: u32,
    seq_num: u32,
    km_local: &[u8],
    message_id: u16,
    scope: &str,
) -> Result<()> {
    buffer.reset();
    coap::build_coap_header(buffer, message_id)?;

    let hex = TUID(*target_tuid).to_hex_upper();
    let hex_str = core::str::from_utf8(&hex).map_err(|_| SigNetError::Encode)?;
    let ep_str = endpoint.to_string();
    let segments = [
        SIGNET_URI_PREFIX, SIGNET_URI_VERSION, scope, "manager", hex_str, &ep_str,
    ];
    write_uri_path_segments(buffer, &segments)?;

    let options = write_options_2076_2204(buffer, manager_tuid, endpoint, mfg_code, session_id, seq_num)?;

    let mut uri_buf = [0u8; URI_STRING_MIN_BUFFER as usize];
    let uri_len = coap::build_manager_uri_string(target_tuid, endpoint, scope, &mut uri_buf)?;
    let uri_string = core::str::from_utf8(&uri_buf[..uri_len])
        .map_err(|_| SigNetError::Encode)?;

    let hmac = compute_hmac_opt(uri_string, &options, tlv_payload, km_local)?;
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, &hmac)?;

    write_packet_payload(buffer, tlv_payload)
}
