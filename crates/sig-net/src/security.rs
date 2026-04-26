use crate::*;
use crate::coap;

pub fn build_sender_id(tuid: &[u8; TUID_LENGTH], endpoint: u16, sender_id: &mut [u8; SENDER_ID_LENGTH]) {
    sender_id[..TUID_LENGTH].copy_from_slice(tuid);
    sender_id[TUID_LENGTH..SENDER_ID_LENGTH].copy_from_slice(&endpoint.to_be_bytes());
}

pub fn build_signet_options_without_hmac(
    buffer: &mut PacketBuffer,
    options: &SigNetOptions,
    prev_option: u16,
) -> Result<()> {
    let mut prev = prev_option;

    prev = encode_opt(buffer, SIGNET_OPTION_SECURITY_MODE, prev, &[options.security_mode])?;
    prev = encode_opt(buffer, SIGNET_OPTION_SENDER_ID, prev, &options.sender_id)?;
    prev = encode_opt(buffer, SIGNET_OPTION_MFG_CODE, prev, &options.mfg_code.to_be_bytes())?;
    prev = encode_opt(buffer, SIGNET_OPTION_SESSION_ID, prev, &options.session_id.to_be_bytes())?;
    encode_opt(buffer, SIGNET_OPTION_SEQ_NUM, prev, &options.seq_num.to_be_bytes())?;

    Ok(())
}

fn encode_opt(buffer: &mut PacketBuffer, opt_num: u16, prev: u16, value: &[u8]) -> Result<u16> {
    coap::encode_coap_option(buffer, opt_num, prev, value)?;
    Ok(opt_num)
}

pub fn encode_hmac_option(
    buffer: &mut PacketBuffer,
    hmac: &[u8; HMAC_SHA256_LENGTH],
    prev_option: u16,
) -> Result<()> {
    coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, prev_option, hmac)
}
