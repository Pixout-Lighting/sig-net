use crate::*;

pub fn encode_tlv(buffer: &mut PacketBuffer, tlv: &TLVBlock) -> Result<()> {
    buffer.write_u16(tlv.type_id)?;
    buffer.write_u16(tlv.length())?;
    buffer.write_bytes(tlv.value)
}

pub fn encode_tid_level(buffer: &mut PacketBuffer, dmx_data: &[u8]) -> Result<()> {
    if dmx_data.is_empty() || dmx_data.len() > MAX_DMX_SLOTS as usize {
        return Err(SigNetError::InvalidArgument);
    }
    let tlv = TLVBlock {
        type_id: TID_LEVEL,
        value: dmx_data,
    };
    encode_tlv(buffer, &tlv)
}

pub fn encode_tid_priority(buffer: &mut PacketBuffer, priority_data: &[u8]) -> Result<()> {
    if priority_data.is_empty() || priority_data.len() > MAX_DMX_SLOTS as usize {
        return Err(SigNetError::InvalidArgument);
    }
    let tlv = TLVBlock {
        type_id: TID_PRIORITY,
        value: priority_data,
    };
    encode_tlv(buffer, &tlv)
}

pub fn encode_tid_sync(buffer: &mut PacketBuffer) -> Result<()> {
    buffer.write_u16(TID_SYNC)?;
    buffer.write_u16(0)
}

pub fn encode_tid_poll(
    buffer: &mut PacketBuffer,
    manager_tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    product_variant_id: u16,
    tuid_lo: &[u8; TUID_LENGTH],
    tuid_hi: &[u8; TUID_LENGTH],
    target_endpoint: u16,
    query_level: u8,
) -> Result<()> {
    buffer.write_u16(TID_POLL)?;
    buffer.write_u16(TID_POLL_VALUE_LEN)?;
    buffer.write_bytes(manager_tuid)?;
    buffer.write_u16(mfg_code)?;
    buffer.write_u16(product_variant_id)?;
    buffer.write_bytes(tuid_lo)?;
    buffer.write_bytes(tuid_hi)?;
    buffer.write_u16(target_endpoint)?;
    buffer.write_byte(query_level)
}

pub fn encode_tid_poll_reply(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    product_variant_id: u16,
    change_count: u16,
) -> Result<()> {
    buffer.write_u16(TID_POLL_REPLY)?;
    buffer.write_u16(TID_POLL_REPLY_VALUE_LEN)?;
    buffer.write_bytes(tuid)?;
    buffer.write_u16(mfg_code)?;
    buffer.write_u16(product_variant_id)?;
    buffer.write_u16(change_count)
}

pub fn encode_tid_rt_protocol_version(buffer: &mut PacketBuffer, protocol_version: u8) -> Result<()> {
    buffer.write_u16(TID_RT_PROTOCOL_VERSION)?;
    buffer.write_u16(1)?;
    buffer.write_byte(protocol_version)
}

pub fn encode_tid_rt_firmware_version(
    buffer: &mut PacketBuffer,
    machine_version_id: u16,
    version_string: &str,
) -> Result<()> {
    let vs = version_string.as_bytes();
    buffer.write_u16(TID_RT_FIRMWARE_VERSION)?;
    buffer.write_u16(2 + vs.len() as u16)?;
    buffer.write_u16(machine_version_id)?;
    buffer.write_bytes(vs)
}

pub fn encode_tid_rt_role_capability(buffer: &mut PacketBuffer, role_capability_bits: u8) -> Result<()> {
    buffer.write_u16(TID_RT_ROLE_CAPABILITY)?;
    buffer.write_u16(1)?;
    buffer.write_byte(role_capability_bits)
}

pub fn build_startup_announce_payload(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    mfg_code: u16,
    product_variant_id: u16,
    firmware_version_id: u16,
    firmware_version_string: &str,
    protocol_version: u8,
    role_capability_bits: u8,
    change_count: u16,
) -> Result<()> {
    encode_tid_poll_reply(buffer, tuid, mfg_code, product_variant_id, change_count)?;
    encode_tid_rt_firmware_version(buffer, firmware_version_id, firmware_version_string)?;
    encode_tid_rt_protocol_version(buffer, protocol_version)?;
    encode_tid_rt_role_capability(buffer, role_capability_bits)
}
