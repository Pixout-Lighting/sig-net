#![allow(clippy::too_many_arguments)]
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
    soem_code: SoemCode,
    tuid_lo: &[u8; TUID_LENGTH],
    tuid_hi: &[u8; TUID_LENGTH],
    target_endpoint: u16,
    query_level: u8,
) -> Result<()> {
    buffer.write_u16(TID_POLL)?;
    buffer.write_u16(TID_POLL_VALUE_LEN)?;
    buffer.write_bytes(manager_tuid)?;
    buffer.write_u32(soem_code)?;
    buffer.write_bytes(tuid_lo)?;
    buffer.write_bytes(tuid_hi)?;
    buffer.write_u16(target_endpoint)?;
    buffer.write_byte(query_level)
}

pub fn encode_tid_poll_reply(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    soem_code: SoemCode,
    change_count: u16,
) -> Result<()> {
    buffer.write_u16(TID_POLL_REPLY)?;
    buffer.write_u16(TID_POLL_REPLY_VALUE_LEN)?;
    buffer.write_bytes(tuid)?;
    buffer.write_u32(soem_code)?;
    buffer.write_u16(change_count)
}

pub fn encode_tid_rt_protocol_version(buffer: &mut PacketBuffer, protocol_version: u8) -> Result<()> {
    buffer.write_u16(TID_RT_PROTOCOL_VERSION)?;
    buffer.write_u16(1)?;
    buffer.write_byte(protocol_version)
}

pub fn encode_tid_rt_firmware_version(
    buffer: &mut PacketBuffer,
    machine_version_id: u32,
    version_string: &str,
) -> Result<()> {
    let vs = version_string.as_bytes();
    buffer.write_u16(TID_RT_FIRMWARE_VERSION)?;
    buffer.write_u16(4 + vs.len() as u16)?;
    buffer.write_u32(machine_version_id)?;
    buffer.write_bytes(vs)
}

pub fn encode_tid_rt_role_capability(buffer: &mut PacketBuffer, role_capability_bits: u8) -> Result<()> {
    buffer.write_u16(TID_RT_ROLE_CAPABILITY)?;
    buffer.write_u16(1)?;
    buffer.write_byte(role_capability_bits)
}

pub fn encode_tid_preview(buffer: &mut PacketBuffer, dmx_data: &[u8]) -> Result<()> {
    if dmx_data.is_empty() || dmx_data.len() > MAX_DMX_SLOTS as usize {
        return Err(SigNetError::InvalidArgument);
    }
    let tlv = TLVBlock {
        type_id: TID_PREVIEW,
        value: dmx_data,
    };
    encode_tlv(buffer, &tlv)
}

/// Timecode: 5 bytes = [hours][minutes][seconds][frames][tc_type]
pub fn encode_tid_timecode(
    buffer: &mut PacketBuffer,
    hours: u8,
    minutes: u8,
    seconds: u8,
    frames: u8,
    tc_type: u8,
) -> Result<()> {
    buffer.write_u16(TID_TIMECODE)?;
    buffer.write_u16(5)?;
    buffer.write_byte(hours)?;
    buffer.write_byte(minutes)?;
    buffer.write_byte(seconds)?;
    buffer.write_byte(frames)?;
    buffer.write_byte(tc_type)
}

/// TID_UNIVERSE: 7 bytes = [universe(u16)][command(u8)][multicast_ip(4)]
pub fn encode_tid_universe(
    buffer: &mut PacketBuffer,
    universe: u16,
    command: u8,
    multicast_ip: &[u8; 4],
) -> Result<()> {
    buffer.write_u16(TID_UNIVERSE)?;
    buffer.write_u16(7)?;
    buffer.write_u16(universe)?;
    buffer.write_byte(command)?;
    buffer.write_bytes(multicast_ip)
}

/// TID_RT_MULT_OVERRIDE: 1 byte = [state]
pub fn encode_tid_rt_mult_override(buffer: &mut PacketBuffer, state: u8) -> Result<()> {
    buffer.write_u16(TID_RT_MULT_OVERRIDE)?;
    buffer.write_u16(1)?;
    buffer.write_byte(state)
}

/// TID_RT_OTW_CAPABILITY: 3 bytes = [listener_port(u16)][protocols_bitfield(u8)]
pub fn encode_tid_rt_otw_capability(
    buffer: &mut PacketBuffer,
    listener_port: u16,
    protocols_bitfield: u8,
) -> Result<()> {
    buffer.write_u16(TID_RT_OTW_CAPABILITY)?;
    buffer.write_u16(3)?;
    buffer.write_u16(listener_port)?;
    buffer.write_byte(protocols_bitfield)
}

/// TID_RT_REBOOT: 5 bytes = [reboot_type(u8)][b'B'][b'O'][b'O'][b'T']
pub fn encode_tid_rt_reboot(buffer: &mut PacketBuffer, reboot_type: u8) -> Result<()> {
    buffer.write_u16(TID_RT_REBOOT)?;
    buffer.write_u16(5)?;
    buffer.write_byte(reboot_type)?;
    buffer.write_bytes(b"BOOT")
}

/// Build On-Boot Notification payload in canonical TLV order per §10.2.5.
///
/// SNACtest enforces the *exact* 6-TLV order below; FIRMWARE_VERSION is
/// deliberately excluded (it belongs in a QUERY_FULL response, not the boot
/// announce — strict V1.0 Managers reject extra TLVs in this packet).
pub fn build_startup_announce_payload(
    buffer: &mut PacketBuffer,
    tuid: &[u8; TUID_LENGTH],
    soem_code: SoemCode,
    protocol_version: u8,
    role_capability_bits: u8,
    endpoint_count: u16,
    change_count: u16,
    mult_override_state: u8,
    otw_capability: Option<(u16, u8)>,
) -> Result<()> {
    // 1. TID_POLL_REPLY
    encode_tid_poll_reply(buffer, tuid, soem_code, change_count)?;
    // 2. TID_RT_PROTOCOL_VERSION
    encode_tid_rt_protocol_version(buffer, protocol_version)?;
    // 3. TID_RT_ROLE_CAPABILITY
    encode_tid_rt_role_capability(buffer, role_capability_bits)?;
    // 4. TID_RT_ENDPOINT_COUNT
    let ec = endpoint_count.to_be_bytes();
    encode_tlv(buffer, &TLVBlock { type_id: TID_RT_ENDPOINT_COUNT, value: &ec })?;
    // 5. TID_RT_MULT_OVERRIDE
    encode_tid_rt_mult_override(buffer, mult_override_state)?;
    // 6. TID_RT_OTW_CAPABILITY (only if supported)
    if let Some((port, protocols)) = otw_capability {
        encode_tid_rt_otw_capability(buffer, port, protocols)?;
    }
    Ok(())
}
