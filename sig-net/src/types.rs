use core::fmt;

use crate::*;

pub type Result<T> = core::result::Result<T, SigNetError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigNetError {
    InvalidArgument,
    BufferFull,
    Crypto,
    Encode,
    Network,
    BufferTooSmall,
    InvalidPacket,
    InvalidOption,
    HmacFailed,
    TestFailure,
    PassphraseTooShort,
    PassphraseTooLong,
    PassphraseInsufficientClasses,
    PassphraseConsecutiveIdentical,
    PassphraseConsecutiveSequential,
}

impl fmt::Display for SigNetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigNetError::InvalidArgument => write!(f, "invalid argument"),
            SigNetError::BufferFull => write!(f, "buffer full"),
            SigNetError::Crypto => write!(f, "cryptographic operation failed"),
            SigNetError::Encode => write!(f, "encoding error"),
            SigNetError::Network => write!(f, "network error"),
            SigNetError::BufferTooSmall => write!(f, "buffer too small"),
            SigNetError::InvalidPacket => write!(f, "invalid packet"),
            SigNetError::InvalidOption => write!(f, "invalid option"),
            SigNetError::HmacFailed => write!(f, "HMAC verification failed"),
            SigNetError::TestFailure => write!(f, "self-test failed"),
            SigNetError::PassphraseTooShort => write!(f, "passphrase too short"),
            SigNetError::PassphraseTooLong => write!(f, "passphrase too long"),
            SigNetError::PassphraseInsufficientClasses => write!(f, "insufficient character classes"),
            SigNetError::PassphraseConsecutiveIdentical => write!(f, "consecutive identical characters"),
            SigNetError::PassphraseConsecutiveSequential => write!(f, "consecutive sequential characters"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoAPHeader {
    pub version: u8,
    pub type_: u8,
    pub token_length: u8,
    pub code: u8,
    pub message_id: u16,
}

impl CoAPHeader {
    pub const SIZE: usize = 4;

    pub fn from_bytes(bytes: &[u8; 4]) -> Self {
        CoAPHeader {
            version: bytes[0] >> 6,
            type_: (bytes[0] >> 4) & 0x03,
            token_length: bytes[0] & 0x0F,
            code: bytes[1],
            message_id: u16::from_be_bytes([bytes[2], bytes[3]]),
        }
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        let vtt = ((self.version & 0x03) << 6) | ((self.type_ & 0x03) << 4) | (self.token_length & 0x0F);
        let mid = self.message_id.to_be_bytes();
        [vtt, self.code, mid[0], mid[1]]
    }

    pub fn new(message_id: u16) -> Self {
        CoAPHeader {
            version: COAP_VERSION,
            type_: COAP_TYPE_NON,
            token_length: 0,
            code: COAP_CODE_POST,
            message_id,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TLVBlock<'a> {
    pub type_id: u16,
    pub value: &'a [u8],
}

impl<'a> TLVBlock<'a> {
    pub fn length(&self) -> u16 {
        self.value.len() as u16
    }
}

#[derive(Debug, Clone)]
pub struct SigNetOptions {
    pub security_mode: u8,
    pub sender_id: [u8; SENDER_ID_LENGTH],
    pub mfg_code: u16,
    pub session_id: u32,
    pub seq_num: u32,
    pub hmac: [u8; HMAC_SHA256_LENGTH],
}

impl Default for SigNetOptions {
    fn default() -> Self {
        SigNetOptions {
            security_mode: 0,
            sender_id: [0u8; SENDER_ID_LENGTH],
            mfg_code: 0,
            session_id: 0,
            seq_num: 0,
            hmac: [0u8; HMAC_SHA256_LENGTH],
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketBuffer {
    buffer: [u8; MAX_UDP_PAYLOAD as usize],
    position: u16,
}

impl PacketBuffer {
    pub fn new() -> Self {
        PacketBuffer {
            buffer: [0u8; MAX_UDP_PAYLOAD as usize],
            position: 0,
        }
    }

    pub fn reset(&mut self) {
        self.position = 0;
        self.buffer.fill(0);
    }

    pub fn position(&self) -> u16 {
        self.position
    }

    pub fn len(&self) -> u16 {
        self.position
    }

    pub fn is_empty(&self) -> bool {
        self.position == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.position as usize]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.position as usize]
    }

    pub fn remaining(&self) -> u16 {
        MAX_UDP_PAYLOAD - self.position
    }

    pub fn has_space(&self, size: u16) -> bool {
        (self.position + size) <= MAX_UDP_PAYLOAD
    }

    pub fn write_byte(&mut self, value: u8) -> Result<()> {
        if !self.has_space(1) {
            return Err(SigNetError::BufferFull);
        }
        self.buffer[self.position as usize] = value;
        self.position += 1;
        Ok(())
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        let len = data.len() as u16;
        if !self.has_space(len) {
            return Err(SigNetError::BufferFull);
        }
        let pos = self.position as usize;
        self.buffer[pos..pos + data.len()].copy_from_slice(data);
        self.position += len;
        Ok(())
    }

    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        if !self.has_space(2) {
            return Err(SigNetError::BufferFull);
        }
        let pos = self.position as usize;
        self.buffer[pos..pos + 2].copy_from_slice(&value.to_be_bytes());
        self.position += 2;
        Ok(())
    }

    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        if !self.has_space(4) {
            return Err(SigNetError::BufferFull);
        }
        let pos = self.position as usize;
        self.buffer[pos..pos + 4].copy_from_slice(&value.to_be_bytes());
        self.position += 4;
        Ok(())
    }

    pub fn seek(&mut self, position: u16) -> Result<()> {
        if position > MAX_UDP_PAYLOAD {
            return Err(SigNetError::InvalidArgument);
        }
        self.position = position;
        Ok(())
    }

    pub fn as_raw(&self) -> &[u8; MAX_UDP_PAYLOAD as usize] {
        &self.buffer
    }

    pub fn as_raw_mut(&mut self) -> &mut [u8; MAX_UDP_PAYLOAD as usize] {
        &mut self.buffer
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ReceiverSenderState {
    pub sender_id: [u8; SENDER_ID_LENGTH],
    pub session_id: u32,
    pub seq_num: u32,
    pub last_packet_time_ms: u32,
    pub total_packets_received: u32,
    pub total_packets_accepted: u32,
}

impl Default for ReceiverSenderState {
    fn default() -> Self {
        ReceiverSenderState {
            sender_id: [0u8; SENDER_ID_LENGTH],
            session_id: 0,
            seq_num: 0,
            last_packet_time_ms: 0,
            total_packets_received: 0,
            total_packets_accepted: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiverStatistics {
    pub total_packets: u32,
    pub accepted_packets: u32,
    pub coap_version_errors: u32,
    pub coap_type_errors: u32,
    pub coap_code_errors: u32,
    pub uri_mismatches: u32,
    pub missing_options: u32,
    pub hmac_failures: u32,
    pub replay_detected: u32,
    pub parse_errors: u32,
    pub last_packet_time_ms: u32,
}

impl Default for ReceiverStatistics {
    fn default() -> Self {
        ReceiverStatistics {
            total_packets: 0,
            accepted_packets: 0,
            coap_version_errors: 0,
            coap_type_errors: 0,
            coap_code_errors: 0,
            uri_mismatches: 0,
            missing_options: 0,
            hmac_failures: 0,
            replay_detected: 0,
            parse_errors: 0,
            last_packet_time_ms: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceivedPacketInfo {
    pub message_id: u16,
    pub sender_tuid: [u8; 6],
    pub endpoint: u16,
    pub mfg_code: u16,
    pub session_id: u32,
    pub seq_num: u32,
    pub dmx_slot_count: u16,
    pub hmac_valid: bool,
    pub session_fresh: bool,
    pub rejection_reason: Option<&'static str>,
    pub timestamp_ms: u32,
}

impl Default for ReceivedPacketInfo {
    fn default() -> Self {
        ReceivedPacketInfo {
            message_id: 0,
            sender_tuid: [0u8; 6],
            endpoint: 0,
            mfg_code: 0,
            session_id: 0,
            seq_num: 0,
            dmx_slot_count: 0,
            hmac_valid: false,
            session_fresh: false,
            rejection_reason: None,
            timestamp_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TUID(pub [u8; TUID_LENGTH]);

impl TUID {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TUID_LENGTH {
            return Err(SigNetError::InvalidArgument);
        }
        let mut arr = [0u8; TUID_LENGTH];
        arr.copy_from_slice(bytes);
        Ok(TUID(arr))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> [u8; TUID_HEX_LENGTH] {
        const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = [0u8; TUID_HEX_LENGTH];
        for i in 0..TUID_LENGTH {
            out[i * 2] = HEX_CHARS[(self.0[i] >> 4) as usize];
            out[i * 2 + 1] = HEX_CHARS[(self.0[i] & 0x0F) as usize];
        }
        out
    }

    pub fn from_hex(hex: &[u8]) -> Result<Self> {
        if hex.len() != TUID_HEX_LENGTH {
            return Err(SigNetError::InvalidArgument);
        }
        let mut arr = [0u8; TUID_LENGTH];
        for i in 0..TUID_LENGTH {
            arr[i] = (hex_char(hex[i * 2])? << 4) | hex_char(hex[i * 2 + 1])?;
        }
        Ok(TUID(arr))
    }
}

fn hex_char(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(SigNetError::InvalidArgument),
    }
}

pub fn increment_sequence(current_seq: u32) -> u32 {
    if current_seq == 0xFFFFFFFF {
        1
    } else {
        current_seq + 1
    }
}

pub fn should_increment_session(seq_num: u32) -> bool {
    seq_num == 0xFFFFFFFF
}

pub fn calculate_multicast_address(universe: u16) -> Result<[u8; 4]> {
    if universe < MIN_UNIVERSE || universe > MAX_UNIVERSE {
        return Err(SigNetError::InvalidArgument);
    }
    let index = ((universe - 1) % 100) + 1;
    Ok([MULTICAST_BASE_OCTET_0, MULTICAST_BASE_OCTET_1, MULTICAST_BASE_OCTET_2, index as u8])
}
