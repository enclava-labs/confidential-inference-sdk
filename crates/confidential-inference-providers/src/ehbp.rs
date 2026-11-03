use ring::{aead, hmac};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{ProviderError, Result};

const KEM_SUITE: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x02";

pub(crate) struct EncryptedRequest {
    pub(crate) enc: [u8; 32],
    pub(crate) body: Vec<u8>,
    pub(crate) exported_secret: [u8; 32],
}

fn error(message: &str) -> ProviderError {
    ProviderError::Adapter(format!("EHBP {message}"))
}

fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut context = hmac::Context::with_key(&key);
    for part in parts {
        context.update(part);
    }
    let mut result = [0; 32];
    result.copy_from_slice(context.sign().as_ref());
    result
}

fn extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    mac(salt, &[b"HPKE-v1", suite, label, ikm])
}

fn expand(suite: &[u8], prk: &[u8], label: &[u8], info: &[u8], len: u16) -> [u8; 32] {
    mac(
        prk,
        &[&len.to_be_bytes(), b"HPKE-v1", suite, label, info, &[1]],
    )
}

pub(crate) fn encrypt(public_key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedRequest> {
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *seed).map_err(|_| error("randomness unavailable"))?;
    encrypt_with_seed(public_key, plaintext, &seed)
}

fn encrypt_with_seed(
    public_key: &[u8; 32],
    plaintext: &[u8],
    seed: &[u8; 32],
) -> Result<EncryptedRequest> {
    if plaintext.is_empty() {
        return Err(error("requires non-empty body"));
    }
    let ciphertext_len = plaintext
        .len()
        .checked_add(aead::AES_256_GCM.tag_len())
        .and_then(|len| u32::try_from(len).ok())
        .ok_or_else(|| error("request body is too large"))?;

    let dkp_prk = Zeroizing::new(extract(KEM_SUITE, &[], b"dkp_prk", seed));
    let secret_bytes = Zeroizing::new(expand(KEM_SUITE, &*dkp_prk, b"sk", &[], 32));
    let secret = StaticSecret::from(*secret_bytes);
    let enc = PublicKey::from(&secret).to_bytes();
    let dh = secret.diffie_hellman(&PublicKey::from(*public_key));
    if !dh.was_contributory() {
        return Err(error("invalid recipient public key"));
    }
    let eae_prk = Zeroizing::new(extract(KEM_SUITE, &[], b"eae_prk", dh.as_bytes()));
    let mut kem_context = [0; 64];
    kem_context[..32].copy_from_slice(&enc);
    kem_context[32..].copy_from_slice(public_key);
    let shared = Zeroizing::new(expand(
        KEM_SUITE,
        &*eae_prk,
        b"shared_secret",
        &kem_context,
        32,
    ));
    let psk_id_hash = extract(HPKE_SUITE, &[], b"psk_id_hash", &[]);
    let info_hash = extract(HPKE_SUITE, &[], b"info_hash", b"ehbp request");
    let mut context = [0; 65];
    context[1..33].copy_from_slice(&psk_id_hash);
    context[33..].copy_from_slice(&info_hash);
    let key_schedule_secret = Zeroizing::new(extract(HPKE_SUITE, &*shared, b"secret", &[]));
    let key = Zeroizing::new(expand(
        HPKE_SUITE,
        &*key_schedule_secret,
        b"key",
        &context,
        32,
    ));
    let nonce = expand(
        HPKE_SUITE,
        &*key_schedule_secret,
        b"base_nonce",
        &context,
        12,
    );
    let exporter = Zeroizing::new(expand(
        HPKE_SUITE,
        &*key_schedule_secret,
        b"exp",
        &context,
        32,
    ));
    let exported_secret = expand(HPKE_SUITE, &*exporter, b"sec", b"ehbp response", 32);

    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &*key)
            .map_err(|_| error("invalid request key"))?,
    );
    let mut body = Vec::with_capacity(4 + ciphertext_len as usize);
    body.extend_from_slice(&ciphertext_len.to_be_bytes());
    body.extend_from_slice(plaintext);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes(&nonce));
    let tag = key
        .seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut body[4..])
        .map_err(|_| error("request encryption failed"))?;
    body.extend_from_slice(tag.as_ref());
    Ok(EncryptedRequest {
        enc,
        body,
        exported_secret,
    })
}

fn nonce_bytes(nonce: &[u8; 32]) -> [u8; 12] {
    nonce[..12].try_into().expect("fixed nonce size")
}

pub(crate) fn decrypt(
    exported_secret: &[u8; 32],
    request_enc: &[u8; 32],
    response_nonce: &[u8],
    body: &[u8],
) -> Result<Vec<u8>> {
    if response_nonce.len() != 32 {
        return Err(error("response nonce must be 32 bytes"));
    }
    let mut salt = [0; 64];
    salt[..32].copy_from_slice(request_enc);
    salt[32..].copy_from_slice(response_nonce);
    let prk = Zeroizing::new(mac(&salt, &[exported_secret]));
    let key = Zeroizing::new(mac(&*prk, &[b"key", &[1]]));
    let nonce_base = mac(&*prk, &[b"nonce", &[1]]);
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &*key)
            .map_err(|_| error("invalid response key"))?,
    );
    let mut plaintext = Vec::new();
    let mut remaining = body;
    let mut seq = 0_u64;
    while !remaining.is_empty() {
        if remaining.len() < 4 {
            return Err(error("truncated chunk length"));
        }
        let len = u32::from_be_bytes(remaining[..4].try_into().expect("length checked")) as usize;
        remaining = &remaining[4..];
        if len == 0 {
            continue;
        }
        if remaining.len() < len {
            return Err(error("truncated ciphertext chunk"));
        }
        let mut chunk = remaining[..len].to_vec();
        remaining = &remaining[len..];
        let mut nonce = nonce_bytes(&nonce_base);
        for (byte, seq_byte) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *byte ^= seq_byte;
        }
        let opened = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut chunk,
            )
            .map_err(|_| error("response authentication failed"))?;
        plaintext.extend_from_slice(opened);
        seq = seq
            .checked_add(1)
            .ok_or_else(|| error("too many response chunks"))?;
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    // CIRCL HPKE sender with recipient seed 0x11 and sender randomness 0x22.
    #[test]
    fn go_ehbp_vector() {
        let public_key: [u8; 32] =
            hex("1a239249ea74403babc01f32df9931a16f71ac8972c461d69fed15640e310639")
                .try_into()
                .unwrap();
        let request = encrypt_with_seed(&public_key, b"request plaintext", &[0x22; 32]).unwrap();
        assert_eq!(
            request.enc.as_slice(),
            hex("e3b9708aaa21a7f1e62a95ee28d1e5d60b0fceed6c68599013a54b318e9e0b15")
        );
        assert_eq!(
            request.body,
            hex("0000002118aa8fb94a3575e4e9110c9126a32eb39bbc5e734ed3b9447f630a38de76a71747")
        );
        assert_eq!(
            request.exported_secret.as_slice(),
            hex("88c260f0e6f62ce2e4002214e8043b6d5a456756e832cb0bf0d2573a62248d5d")
        );
        let mut response =
            hex("00000022bc7f262bb9cc9116a91e91190ea7bafe0a2fcf81253daf345b068d0cfdf12f8c4eb3");
        assert_eq!(
            decrypt(
                &request.exported_secret,
                &request.enc,
                &[0x33; 32],
                &response
            )
            .unwrap(),
            b"response plaintext"
        );
        response.extend_from_slice(&[0, 0, 0, 0]);
        response.extend_from_slice(&hex(
            "000000176853762c8b1942bc41b1d4117d6118af63c1dd3a966658",
        ));
        assert_eq!(
            decrypt(
                &request.exported_secret,
                &request.enc,
                &[0x33; 32],
                &response
            )
            .unwrap(),
            b"response plaintext second"
        );
        response[45] ^= 1;
        assert!(decrypt(
            &request.exported_secret,
            &request.enc,
            &[0x33; 32],
            &response
        )
        .is_err());
    }

    #[test]
    fn rejects_tampering_and_bad_inputs() {
        let enc: [u8; 32] = hex("e3b9708aaa21a7f1e62a95ee28d1e5d60b0fceed6c68599013a54b318e9e0b15")
            .try_into()
            .unwrap();
        let secret: [u8; 32] =
            hex("88c260f0e6f62ce2e4002214e8043b6d5a456756e832cb0bf0d2573a62248d5d")
                .try_into()
                .unwrap();
        let response =
            hex("00000022bc7f262bb9cc9116a91e91190ea7bafe0a2fcf81253daf345b068d0cfdf12f8c4eb3");
        let mut altered = response.clone();
        altered[4] ^= 1;
        assert!(decrypt(&secret, &enc, &[0x33; 32], &altered).is_err());
        assert!(decrypt(&secret, &enc, &[0x32; 32], &response).is_err());
        let mut bad_enc = enc;
        bad_enc[0] ^= 1;
        assert!(decrypt(&secret, &bad_enc, &[0x33; 32], &response).is_err());
        let mut bad_secret = secret;
        bad_secret[0] ^= 1;
        assert!(decrypt(&bad_secret, &enc, &[0x33; 32], &response).is_err());
        assert!(decrypt(&secret, &enc, &[0; 31], &response).is_err());
        assert!(decrypt(&secret, &enc, &[0x33; 32], &response[..3]).is_err());
        assert!(decrypt(&secret, &enc, &[0x33; 32], &response[..response.len() - 1]).is_err());
        assert!(encrypt_with_seed(&[0; 32], b"request", &[0x22; 32]).is_err());
        assert!(encrypt_with_seed(&enc, b"", &[0x22; 32]).is_err());
    }
}
