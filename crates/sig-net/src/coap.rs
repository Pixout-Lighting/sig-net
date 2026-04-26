use crate::*;

fn option_nibble(value: u16) -> (u8, u8) {
    match value {
        0..=12 => (value as u8, 0),
        13..=268 => (13, 1),
        _ => (14, 2),  // >= 269
    }
}

fn encode_option_nibble(buffer: &mut PacketBuffer, delta: u16, length: u16) -> Result<()> {
    let (delta_nib, delta_ext) = option_nibble(delta);
    let (len_nib, len_ext) = option_nibble(length);

    let nibble = (delta_nib << 4) | len_nib;
    buffer.write_byte(nibble)?;

    match delta_ext {
        1 => buffer.write_byte((delta - 13) as u8)?,
        2 => buffer.write_u16(delta - 269)?,
        _ => {}
    }

    match len_ext {
        1 => buffer.write_byte((length - 13) as u8)?,
        2 => buffer.write_u16(length - 269)?,
        _ => {}
    }

    Ok(())
}

pub fn encode_coap_option(
    buffer: &mut PacketBuffer,
    option_number: u16,
    prev_option: u16,
    option_value: &[u8],
) -> Result<()> {
    let delta = option_number
        .checked_sub(prev_option)
        .ok_or(SigNetError::InvalidArgument)?;
    encode_option_nibble(buffer, delta, option_value.len() as u16)?;
    buffer.write_bytes(option_value)
}

pub fn build_coap_header(buffer: &mut PacketBuffer, message_id: u16) -> Result<()> {
    let header = CoAPHeader::new(message_id);
    buffer.write_bytes(&header.to_bytes())
}

pub fn build_uri_path_options(buffer: &mut PacketBuffer, universe: u16) -> Result<()> {
    if universe < MIN_UNIVERSE || universe > MAX_UNIVERSE {
        return Err(SigNetError::InvalidArgument);
    }

    let segments = [
        SIGNET_URI_PREFIX,
        SIGNET_URI_VERSION,
        SIGNET_URI_SCOPE_DEFAULT,
        SIGNET_URI_LEVEL,
    ];

    let mut prev_option: u16 = 0;
    for &segment in &segments {
        encode_coap_option(buffer, COAP_OPTION_URI_PATH, prev_option, segment.as_bytes())?;
        prev_option = COAP_OPTION_URI_PATH;
    }

    let universe_str = universe.to_string();
    encode_coap_option(buffer, COAP_OPTION_URI_PATH, prev_option, universe_str.as_bytes())
}

pub fn build_uri_string(universe: u16, uri_output: &mut [u8]) -> Result<usize> {
    if universe < MIN_UNIVERSE || universe > MAX_UNIVERSE {
        return Err(SigNetError::InvalidArgument);
    }
    let s = format!(
        "/{}/{}/{}/{}/{}",
        SIGNET_URI_PREFIX,
        SIGNET_URI_VERSION,
        SIGNET_URI_SCOPE_DEFAULT,
        SIGNET_URI_LEVEL,
        universe
    );
    let bytes = s.as_bytes();
    if bytes.len() > uri_output.len() {
        return Err(SigNetError::InvalidArgument);
    }
    uri_output[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

pub fn build_node_uri_string(
    tuid: &[u8; TUID_LENGTH],
    endpoint: u16,
    uri_output: &mut [u8],
) -> Result<usize> {
    let hex = TUID(*tuid).to_hex();
    let hex_str = core::str::from_utf8(&hex)
        .map_err(|_| SigNetError::Encode)?;
    let s = format!(
        "/{}/{}/{}/{}/{}/{}",
        SIGNET_URI_PREFIX,
        SIGNET_URI_VERSION,
        SIGNET_URI_SCOPE_DEFAULT,
        SIGNET_URI_NODE,
        hex_str,
        endpoint
    );
    let bytes = s.as_bytes();
    if bytes.len() > uri_output.len() {
        return Err(SigNetError::InvalidArgument);
    }
    uri_output[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}
