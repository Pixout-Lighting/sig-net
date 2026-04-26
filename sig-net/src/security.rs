use crate::*;

pub fn build_sender_id(tuid: &[u8; TUID_LENGTH], endpoint: u16, sender_id: &mut [u8; SENDER_ID_LENGTH]) {
    sender_id[..TUID_LENGTH].copy_from_slice(tuid);
    let ep_bytes = endpoint.to_be_bytes();
    sender_id[TUID_LENGTH] = ep_bytes[0];
    sender_id[TUID_LENGTH + 1] = ep_bytes[1];
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
    crate::coap::encode_coap_option(buffer, opt_num, prev, value)?;
    Ok(opt_num)
}

pub fn calculate_and_encode_hmac(
    buffer: &mut PacketBuffer,
    uri_string: &str,
    options: &mut SigNetOptions,
    payload: &[u8],
    signing_key: &[u8],
    prev_option: u16,
) -> Result<()> {
    let input_len = uri_string.len() + 1 + SENDER_ID_LENGTH + 2 + 4 + 4 + payload.len();
    let mut hmac_input = vec![0u8; input_len];
    crate::crypto::build_hmac_input(uri_string, options, payload, &mut hmac_input)?;
    crate::crypto::hmac_sha256(signing_key, &hmac_input, &mut options.hmac)?;

    crate::coap::encode_coap_option(buffer, SIGNET_OPTION_HMAC, prev_option, &options.hmac)
}
