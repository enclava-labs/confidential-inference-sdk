use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{digest, signature};
use serde_json::Value;
use x509_cert::{
    der::{asn1::OctetString, DateTime, Decode, Encode},
    Certificate,
};

const SCT_OID: &str = "1.3.6.1.4.1.11129.2.4.2";
const POISON_OID: &str = "1.3.6.1.4.1.11129.2.4.3";
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], String> {
    if len > input.len() {
        return Err("truncated SCT".into());
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn vector16<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let n = take(input, 2)?;
    take(input, u16::from_be_bytes([n[0], n[1]]) as usize)
}

// Trusted root timestamps are RFC 3339 UTC strings; preserve subsecond boundaries.
pub(crate) fn timestamp_ns(s: &str) -> Option<u128> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last()? != b'Z'
    {
        return None;
    }
    fn number(b: &[u8]) -> Option<u32> {
        b.iter().try_fold(0u32, |n, c| {
            if c.is_ascii_digit() {
                Some(n * 10 + u32::from(c - b'0'))
            } else {
                None
            }
        })
    }
    let date = DateTime::new(
        number(&b[0..4])? as u16,
        number(&b[5..7])? as u8,
        number(&b[8..10])? as u8,
        number(&b[11..13])? as u8,
        number(&b[14..16])? as u8,
        number(&b[17..19])? as u8,
    )
    .ok()?;
    let fraction = &b[19..b.len() - 1];
    let nanos = if fraction.is_empty() {
        0
    } else {
        if fraction[0] != b'.' || fraction.len() < 2 || fraction.len() > 10 {
            return None;
        }
        number(&fraction[1..])? * 10u32.pow((10 - fraction.len()) as u32)
    };
    Some(u128::from(date.unix_duration().as_secs()) * 1_000_000_000 + u128::from(nanos))
}

fn verify_one(sct: &[u8], tbs: &[u8], issuer_hash: &[u8], logs: &[Value]) -> Result<(), String> {
    let mut input = sct;
    if take(&mut input, 1)? != [0] {
        return Err("unsupported SCT version".into());
    }
    let id = take(&mut input, 32)?;
    let timestamp = take(&mut input, 8)?;
    let millis = u64::from_be_bytes(timestamp.try_into().map_err(|_| "invalid SCT timestamp")?);
    let extensions = vector16(&mut input)?;
    if take(&mut input, 2)? != [4, 3] {
        return Err("unsupported SCT signature algorithm".into());
    }
    let signature_bytes = vector16(&mut input)?;
    if !input.is_empty() {
        return Err("trailing SCT data".into());
    }
    if tbs.len() > 0xff_ffff {
        return Err("precertificate too large".into());
    }

    let mut signed = Vec::with_capacity(47 + tbs.len() + extensions.len());
    signed.extend_from_slice(&[0, 0]);
    signed.extend_from_slice(timestamp);
    signed.extend_from_slice(&[0, 1]);
    signed.extend_from_slice(issuer_hash);
    let len = tbs.len() as u32;
    signed.extend_from_slice(&len.to_be_bytes()[1..]);
    signed.extend_from_slice(tbs);
    signed.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    signed.extend_from_slice(extensions);

    for log in logs {
        if log.get("hashAlgorithm").and_then(Value::as_str) != Some("SHA2_256") {
            continue;
        }
        let Some(key) = log.get("publicKey") else {
            continue;
        };
        if key.get("keyDetails").and_then(Value::as_str) != Some("PKIX_ECDSA_P256_SHA_256") {
            continue;
        }
        let Some(raw) = key
            .get("rawBytes")
            .and_then(Value::as_str)
            .and_then(|s| STANDARD.decode(s).ok())
        else {
            continue;
        };
        let Some(log_id) = log
            .pointer("/logId/keyId")
            .and_then(Value::as_str)
            .and_then(|s| STANDARD.decode(s).ok())
        else {
            continue;
        };
        if log_id != id
            || digest::digest(&digest::SHA256, &raw).as_ref() != id
            || raw.len() != P256_SPKI_PREFIX.len() + 65
            || !raw.starts_with(P256_SPKI_PREFIX)
        {
            continue;
        }
        let Some(start) = key
            .pointer("/validFor/start")
            .and_then(Value::as_str)
            .and_then(timestamp_ns)
        else {
            continue;
        };
        let time = u128::from(millis) * 1_000_000;
        if time < start {
            continue;
        }
        if let Some(end) = key.pointer("/validFor/end") {
            let Some(end) = end.as_str().and_then(timestamp_ns) else {
                continue;
            };
            if time > end {
                continue;
            }
        }
        if signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            &raw[P256_SPKI_PREFIX.len()..],
        )
        .verify(&signed, signature_bytes)
        .is_ok()
        {
            return Ok(());
        }
    }
    Err("no trusted CT log verified the SCT".into())
}
// The certificate API exposes the TBS immutably, so rebuild its extension wrapper.
fn der_value(input: &[u8], tag: u8) -> Result<&[u8], String> {
    if input.len() < 2 || input[0] != tag {
        return Err("invalid certificate DER".into());
    }
    let first = input[1];
    let (len, header) = if first < 128 {
        (first as usize, 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || input.len() < 2 + count {
            return Err("invalid certificate DER length".into());
        }
        let mut len = 0usize;
        for &byte in &input[2..2 + count] {
            len = len
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(byte)))
                .ok_or("invalid certificate DER length")?;
        }
        (len, 2 + count)
    };
    if input.len().checked_sub(header) != Some(len) {
        return Err("invalid certificate DER length".into());
    }
    Ok(&input[header..])
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 10);
    out.push(tag);
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let len = content.len().to_be_bytes();
        let start = len
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(len.len() - 1);
        out.push(0x80 | (len.len() - start) as u8);
        out.extend_from_slice(&len[start..]);
    }
    out.extend_from_slice(content);
    out
}

fn precert_tbs(
    tbs: &[u8],
    extensions: &[x509_cert::ext::Extension],
    sct_index: usize,
) -> Result<Vec<u8>, String> {
    let body = der_value(tbs, 0x30)?;
    let mut all_extensions = Vec::new();
    let mut remaining = Vec::new();
    for (i, ext) in extensions.iter().enumerate() {
        let encoded = ext.to_der().map_err(|e| e.to_string())?;
        all_extensions.extend_from_slice(&encoded);
        if i != sct_index {
            remaining.extend_from_slice(&encoded);
        }
    }
    let old = der_wrap(0xa3, &der_wrap(0x30, &all_extensions));
    let prefix = body
        .strip_suffix(old.as_slice())
        .ok_or("invalid certificate extensions")?;
    let mut rebuilt = prefix.to_vec();
    rebuilt.extend_from_slice(&der_wrap(0xa3, &der_wrap(0x30, &remaining)));
    Ok(der_wrap(0x30, &rebuilt))
}

pub(crate) fn verify_sct(
    cert_der: &[u8],
    issuer_der: &[u8],
    trusted_root: &Value,
) -> Result<(), String> {
    let cert =
        Certificate::from_der(cert_der).map_err(|e| format!("invalid SCT certificate: {e}"))?;
    let issuer =
        Certificate::from_der(issuer_der).map_err(|e| format!("invalid SCT issuer: {e}"))?;
    let issuer_spki = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| e.to_string())?;
    let issuer_hash = digest::digest(&digest::SHA256, &issuer_spki);
    let extensions = cert
        .tbs_certificate()
        .extensions()
        .ok_or("missing SCT extension")?;
    let mut sct_index = None;
    for (i, ext) in extensions.iter().enumerate() {
        let oid = ext.extn_id.to_string();
        if oid == POISON_OID {
            return Err("final certificate contains CT poison".into());
        }
        if oid == SCT_OID && (sct_index.replace(i).is_some() || ext.critical) {
            return Err("invalid SCT extension".into());
        }
    }
    let sct_index = sct_index.ok_or("missing SCT extension")?;
    let sct_list = OctetString::from_der(extensions[sct_index].extn_value.as_bytes())
        .map_err(|e| format!("invalid SCT extension: {e}"))?;
    let mut list_bytes = sct_list.as_bytes();
    let mut list = vector16(&mut list_bytes)?;
    if !list_bytes.is_empty() || list.is_empty() {
        return Err("invalid SCT list".into());
    }
    let encoded_tbs = cert.tbs_certificate().to_der().map_err(|e| e.to_string())?;
    let tbs = precert_tbs(&encoded_tbs, extensions, sct_index)?;
    let logs = trusted_root
        .get("ctlogs")
        .and_then(Value::as_array)
        .ok_or("missing trusted CT logs")?;
    let mut verified = false;
    while !list.is_empty() {
        let sct = vector16(&mut list)?;
        if verify_one(sct, &tbs, issuer_hash.as_ref(), logs).is_ok() {
            verified = true;
        }
    }
    if verified {
        Ok(())
    } else {
        Err("no trusted SCT verified".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_sct_and_untrusted_log() {
        let bundle: Value =
            serde_json::from_str(include_str!("sigstore_bundle_fixture.json")).unwrap();
        let mut root: Value =
            serde_json::from_str(include_str!("sigstore_trusted_root.json")).unwrap();
        let leaf = STANDARD
            .decode(
                bundle["verificationMaterial"]["certificate"]["rawBytes"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let issuer = STANDARD
            .decode(
                root["certificateAuthorities"][1]["certChain"]["certificates"][0]["rawBytes"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert!(verify_sct(&leaf, &issuer, &root).is_ok());
        let wrong_issuer = STANDARD
            .decode(
                root["certificateAuthorities"][0]["certChain"]["certificates"][0]["rawBytes"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert!(verify_sct(&leaf, &wrong_issuer, &root).is_err());
        root["ctlogs"][1]["publicKey"]["validFor"]["end"] =
            serde_json::json!("2022-10-31T23:59:59.999Z");
        assert!(verify_sct(&leaf, &issuer, &root).is_err());
        root["ctlogs"] = serde_json::json!([]);
        assert!(verify_sct(&leaf, &issuer, &root).is_err());
    }

    #[test]
    fn timestamp_boundaries_are_precise() {
        assert_eq!(
            timestamp_ns("2022-10-31T23:59:59.999Z").unwrap() % 1_000_000_000,
            999_000_000
        );
        assert!(timestamp_ns("2022-02-29T00:00:00Z").is_none());
        assert!(timestamp_ns("2022-10-31T23:59:59.Z").is_none());
    }
}
