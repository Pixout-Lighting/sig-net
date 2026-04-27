use crate::*;
use crate::util::hex_char;

pub struct PacketReader<'a> {
    buffer: &'a [u8],
    position: u16,
}

impl<'a> PacketReader<'a> {
    pub fn new(buffer: &'a [u8], size: u16) -> Self {
        let size = (size as usize).min(buffer.len());
        PacketReader {
            buffer: &buffer[..size],
            position: 0,
        }
    }

    pub fn position(&self) -> u16 {
        self.position
    }

    pub fn remaining(&self) -> u16 {
        (self.buffer.len() as u16) - self.position
    }

    pub fn can_read(&self, bytes: u16) -> bool {
        (self.position + bytes) <= self.buffer.len() as u16
    }

    pub fn read_byte(&mut self) -> Result<u8> {
        if !self.can_read(1) {
            return Err(SigNetError::BufferTooSmall);
        }
        let val = self.buffer[self.position as usize];
        self.position += 1;
        Ok(val)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        if !self.can_read(2) {
            return Err(SigNetError::BufferTooSmall);
        }
        let val = u16::from_be_bytes([
            self.buffer[self.position as usize],
            self.buffer[(self.position + 1) as usize],
        ]);
        self.position += 2;
        Ok(val)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if !self.can_read(4) {
            return Err(SigNetError::BufferTooSmall);
        }
        let val = u32::from_be_bytes([
            self.buffer[self.position as usize],
            self.buffer[(self.position + 1) as usize],
            self.buffer[(self.position + 2) as usize],
            self.buffer[(self.position + 3) as usize],
        ]);
        self.position += 4;
        Ok(val)
    }

    pub fn read_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        let count = dest.len() as u16;
        if !self.can_read(count) {
            return Err(SigNetError::BufferTooSmall);
        }
        let start = self.position as usize;
        dest.copy_from_slice(&self.buffer[start..start + count as usize]);
        self.position += count;
        Ok(())
    }

    pub fn skip(&mut self, count: u16) -> Result<()> {
        if !self.can_read(count) {
            return Err(SigNetError::BufferTooSmall);
        }
        self.position += count;
        Ok(())
    }

    pub fn peek_byte(&self) -> Result<u8> {
        if !self.can_read(1) {
            return Err(SigNetError::BufferTooSmall);
        }
        Ok(self.buffer[self.position as usize])
    }

    pub fn current_ptr(&self) -> &'a [u8] {
        &self.buffer[self.position as usize..]
    }

    pub fn parse_coap_header(&mut self) -> Result<CoAPHeader> {
        if !self.can_read(CoAPHeader::SIZE as u16) {
            return Err(SigNetError::BufferTooSmall);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[self.position as usize..self.position as usize + 4]);
        self.position += 4;
        Ok(CoAPHeader::from_bytes(&bytes))
    }

    pub fn skip_token(&mut self, token_length: u8) -> Result<()> {
        self.skip(token_length as u16)
    }

    /// Parse a single CoAP option. Returns (delta, length, value_slice).
    pub fn parse_coap_option(&mut self) -> Result<(u16, u16, &'a [u8])> {
        let nibble = self.read_byte()?;
        let delta_nib = nibble >> 4;
        let len_nib = nibble & 0x0F;

        let delta = match delta_nib {
            0..=12 => delta_nib as u16,
            13 => COAP_OPTION_EXT8_BASE + self.read_byte()? as u16,
            14 => COAP_OPTION_EXT16_BASE + self.read_u16()?,
            _ => return Err(SigNetError::InvalidOption),
        };

        let length = match len_nib {
            0..=12 => len_nib as u16,
            13 => COAP_OPTION_EXT8_BASE + self.read_byte()? as u16,
            14 => COAP_OPTION_EXT16_BASE + self.read_u16()?,
            _ => return Err(SigNetError::InvalidOption),
        };

        if !self.can_read(length) {
            return Err(SigNetError::BufferTooSmall);
        }
        let start = self.position as usize;
        self.skip(length)?;
        let value = &self.buffer[start..start + length as usize];

        Ok((delta, length, value))
    }

    /// Parse all 6 SigNet options (2076–2236) from the current position.
    /// Stops at the payload marker (0xFF) — all options including HMAC must precede it.
    /// Leaves the reader positioned at the first byte of the payload.
    pub fn parse_signet_options(&mut self) -> Result<SigNetOptions> {
        let mut options = SigNetOptions::default();
        let mut prev_option: u16 = 0;
        let mut seen_hmac = false;

        loop {
            if !self.can_read(1) {
                break;
            }
            let peek = self.peek_byte()?;
            if peek == COAP_PAYLOAD_MARKER {
                self.read_byte()?; // consume marker; reader now sits at payload start
                break;
            }

            let (delta, _len, value) = self.parse_coap_option()?;
            let opt_num = prev_option + delta;
            prev_option = opt_num;

            if Self::apply_option(&mut options, opt_num, value) {
                seen_hmac = true;
            }
        }

        if !seen_hmac {
            return Err(SigNetError::InvalidOption);
        }

        Ok(options)
    }

    fn apply_option(options: &mut SigNetOptions, opt_num: u16, value: &[u8]) -> bool {
        match opt_num {
            SIGNET_OPTION_SECURITY_MODE => {
                if !value.is_empty() {
                    options.security_mode = value[0];
                }
                false
            }
            SIGNET_OPTION_SENDER_ID => {
                let len = value.len().min(SENDER_ID_LENGTH);
                options.sender_id[..len].copy_from_slice(&value[..len]);
                false
            }
            SIGNET_OPTION_MFG_CODE => {
                if value.len() >= 2 {
                    options.mfg_code = u16::from_be_bytes([value[0], value[1]]);
                }
                false
            }
            SIGNET_OPTION_SESSION_ID => {
                if value.len() >= 4 {
                    options.session_id =
                        u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                }
                false
            }
            SIGNET_OPTION_SEQ_NUM => {
                if value.len() >= 4 {
                    options.seq_num =
                        u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                }
                false
            }
            SIGNET_OPTION_HMAC => {
                let len = value.len().min(HMAC_SHA256_LENGTH);
                options.hmac[..len].copy_from_slice(&value[..len]);
                true
            }
            _ => false,
        }
    }

    pub fn parse_tlv_block(&mut self) -> Result<TLVBlock<'a>> {
        let type_id = self.read_u16()?;
        let length = self.read_u16()?;
        let start = self.position as usize;
        self.skip(length)?;
        Ok(TLVBlock {
            type_id,
            value: &self.buffer[start..start + length as usize],
        })
    }

    pub fn extract_uri_string(&mut self, uri_string: &mut [u8]) -> Result<usize> {
        let mut prev_option: u16 = 0;
        let mut pos = 0;

        loop {
            if !self.can_read(1) {
                break;
            }
            let peek = self.peek_byte()?;
            if peek == COAP_PAYLOAD_MARKER || peek == 0 {
                break;
            }

            let (delta, _len, value) = self.parse_coap_option()?;
            let opt_num = prev_option + delta;
            prev_option = opt_num;

            if opt_num == COAP_OPTION_URI_PATH {
                if pos < uri_string.len() {
                    uri_string[pos] = b'/';
                    pos += 1;
                }
                if pos + value.len() <= uri_string.len() {
                    uri_string[pos..pos + value.len()].copy_from_slice(value);
                    pos += value.len();
                } else {
                    return Err(SigNetError::BufferTooSmall);
                }
            }
        }

        Ok(pos)
    }
}

pub fn parse_tid_level(tlv: &TLVBlock, dmx_data: &mut [u8]) -> Result<u16> {
    if tlv.type_id != TID_LEVEL {
        return Err(SigNetError::InvalidArgument);
    }
    if tlv.value.len() > MAX_DMX_SLOTS as usize {
        return Err(SigNetError::InvalidPacket);
    }
    dmx_data[..tlv.value.len()].copy_from_slice(tlv.value);
    Ok(tlv.value.len() as u16)
}

/// Parse TID_TIMECODE (0x0202, Length=5) → (hours, minutes, seconds, frames, tc_type)
pub fn parse_tid_timecode(tlv: &TLVBlock) -> Result<(u8, u8, u8, u8, u8)> {
    if tlv.type_id != TID_TIMECODE {
        return Err(SigNetError::InvalidArgument);
    }
    if tlv.value.len() != 5 {
        return Err(SigNetError::InvalidPacket);
    }
    Ok((tlv.value[0], tlv.value[1], tlv.value[2], tlv.value[3], tlv.value[4]))
}

/// Parse TID_PATCH (0x0203, Length=7) → (universe, command, multicast_ip)
pub fn parse_tid_patch(tlv: &TLVBlock) -> Result<(u16, u8, [u8; 4])> {
    if tlv.type_id != TID_PATCH {
        return Err(SigNetError::InvalidArgument);
    }
    if tlv.value.len() != 7 {
        return Err(SigNetError::InvalidPacket);
    }
    let universe = u16::from_be_bytes([tlv.value[0], tlv.value[1]]);
    let command = tlv.value[2];
    let mut ip = [0u8; 4];
    ip.copy_from_slice(&tlv.value[3..7]);
    Ok((universe, command, ip))
}

pub fn parse_hex_bytes(text: &[u8], out_bytes: &mut [u8], byte_count: u16) -> Result<()> {
    let text = if text.starts_with(b"0x") || text.starts_with(b"0X") {
        &text[2..]
    } else {
        text
    };
    // stack buffer: max byte_count is 32 (K0) → 64 hex chars; 70 gives headroom
    let mut stack_buf = [0u8; 70];
    let mut stack_len = 0usize;
    for &b in text {
        if !b.is_ascii_whitespace() {
            if stack_len >= stack_buf.len() {
                return Err(SigNetError::InvalidArgument);
            }
            stack_buf[stack_len] = b;
            stack_len += 1;
        }
    }
    let text = &stack_buf[..stack_len];
    let expected = byte_count as usize * 2;
    if text.len() != expected {
        return Err(SigNetError::InvalidArgument);
    }
    for i in 0..byte_count as usize {
        out_bytes[i] = (hex_char(text[i * 2])? << 4) | hex_char(text[i * 2 + 1])?;
    }
    Ok(())
}
