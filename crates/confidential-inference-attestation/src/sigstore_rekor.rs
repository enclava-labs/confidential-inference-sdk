use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::{digest, signature};
use serde_json::{json, Value};
use x509_cert::der::DateTime;

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or invalid Rekor {name}"))
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|_| "invalid Rekor base64".into())
}

fn number(value: &Value, name: &str) -> Result<u64, String> {
    let v = value
        .get(name)
        .ok_or_else(|| format!("missing Rekor {name}"))?;
    let n = if let Some(s) = v.as_str() {
        s.parse().ok()
    } else {
        v.as_u64()
    };
    n.filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or_else(|| format!("invalid Rekor {name}"))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to String");
    }
    out
}

fn time(value: &str) -> Result<u64, String> {
    let b = value.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err("unsupported Rekor key validity time".into());
    }
    let part = |a, z| -> Result<u16, String> {
        let bytes: &[u8] = &b[a..z];
        if !bytes.iter().all(u8::is_ascii_digit) {
            return Err("invalid Rekor key validity time".into());
        }
        std::str::from_utf8(bytes)
            .map_err(|_| "invalid time".to_string())?
            .parse()
            .map_err(|_| "invalid time".into())
    };
    let dt = DateTime::new(
        part(0, 4)?,
        part(5, 7)? as u8,
        part(8, 10)? as u8,
        part(11, 13)? as u8,
        part(14, 16)? as u8,
        part(17, 19)? as u8,
    )
    .map_err(|_| "invalid Rekor key validity time")?;
    Ok(dt.unix_duration().as_secs())
}

fn verify_signature(key: &[u8], details: &str, message: &[u8], sig: &[u8]) -> Result<(), String> {
    const P256: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    const ED25519: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let (algorithm, raw): (&dyn signature::VerificationAlgorithm, &[u8]) = match details {
        "PKIX_ECDSA_P256_SHA_256" if key.len() == P256.len() + 65 => (
            &signature::ECDSA_P256_SHA256_ASN1,
            key.strip_prefix(P256).ok_or("invalid Rekor P-256 key")?,
        ),
        "PKIX_ED25519" if key.len() == ED25519.len() + 32 => (
            &signature::ED25519,
            key.strip_prefix(ED25519)
                .ok_or("invalid Rekor Ed25519 key")?,
        ),
        _ => return Err("unsupported Rekor key".into()),
    };
    signature::UnparsedPublicKey::new(algorithm, raw)
        .verify(message, sig)
        .map_err(|_| "invalid Rekor signature".into())
}

fn verify_binding(body: &Value, envelope: &Value, certificate: &[u8]) -> Result<(), String> {
    if field(body, "kind")? != "dsse" || field(body, "apiVersion")? != "0.0.1" {
        return Err("unsupported Rekor entry kind".into());
    }
    let spec = &body["spec"];
    let payload_hash = &spec["payloadHash"];
    if field(payload_hash, "algorithm")? != "sha256"
        || field(payload_hash, "value")?
            != hex(digest::digest(&digest::SHA256, &decode(field(envelope, "payload")?)?).as_ref())
    {
        return Err("Rekor payload hash mismatch".into());
    }
    // Rekor hashes the submitted envelope's raw JSON, which the bundle does not retain.
    if field(&spec["envelopeHash"], "algorithm")? != "sha256"
        || field(&spec["envelopeHash"], "value")?.len() != 64
        || !field(&spec["envelopeHash"], "value")?
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid Rekor envelope hash".into());
    }
    let signatures = spec["signatures"]
        .as_array()
        .ok_or("missing Rekor signatures")?;
    let env_signatures = envelope["signatures"]
        .as_array()
        .ok_or("missing DSSE signatures")?;
    if signatures.len() != 1
        || env_signatures.len() != 1
        || decode(field(&signatures[0], "signature")?)?
            != decode(field(&env_signatures[0], "sig")?)?
    {
        return Err("Rekor DSSE signature mismatch".into());
    }
    let pem = decode(field(&signatures[0], "verifier")?)?;
    let pem = std::str::from_utf8(&pem).map_err(|_| "invalid Rekor certificate PEM")?;
    let contents = pem
        .strip_prefix("-----BEGIN CERTIFICATE-----\n")
        .and_then(|s| s.strip_suffix("-----END CERTIFICATE-----\n"))
        .ok_or("invalid Rekor certificate PEM")?;
    let contents: String = contents
        .chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .collect();
    if decode(&contents)? != certificate {
        return Err("Rekor certificate mismatch".into());
    }
    Ok(())
}

fn verify_proof(
    proof: &Value,
    body: &[u8],
    key: &[u8],
    details: &str,
    log_id: &[u8],
) -> Result<(), String> {
    let index = number(proof, "logIndex")?;
    let size = number(proof, "treeSize")?;
    if index >= size {
        return Err("invalid Rekor inclusion index".into());
    }
    let hashes = proof["hashes"]
        .as_array()
        .ok_or("missing Rekor inclusion hashes")?;
    let inner = (u64::BITS - (index ^ (size - 1)).leading_zeros()) as usize;
    let border = if inner == 64 {
        0
    } else {
        (index >> inner).count_ones() as usize
    };
    if hashes.len() != inner + border {
        return Err("invalid Rekor inclusion path length".into());
    }
    let mut leaf = Vec::with_capacity(1 + body.len());
    leaf.push(0);
    leaf.extend_from_slice(body);
    let mut current = digest::digest(&digest::SHA256, &leaf).as_ref().to_vec();
    for (i, hash) in hashes.iter().enumerate() {
        let hash = decode(hash.as_str().ok_or("invalid Rekor inclusion hash")?)?;
        if hash.len() != 32 {
            return Err("invalid Rekor inclusion hash length".into());
        }
        let mut node = [0u8; 65];
        node[0] = 1;
        if i >= inner || ((index >> i) & 1) == 1 {
            node[1..33].copy_from_slice(&hash);
            node[33..].copy_from_slice(&current);
        } else {
            node[1..33].copy_from_slice(&current);
            node[33..].copy_from_slice(&hash);
        }
        current = digest::digest(&digest::SHA256, &node).as_ref().to_vec();
    }
    if current != decode(field(proof, "rootHash")?)? {
        return Err("Rekor inclusion root mismatch".into());
    }
    let checkpoint = field(&proof["checkpoint"], "envelope")?;
    let (text, signatures) = checkpoint
        .split_once("\n\n")
        .ok_or("invalid Rekor checkpoint")?;
    if signatures.lines().nth(8).is_some() {
        return Err("too many Rekor checkpoint signature lines".into());
    }
    let mut lines = text.lines();
    let origin = lines.next().ok_or("missing checkpoint origin")?;
    if origin.is_empty()
        || lines.next().and_then(|s| s.parse::<u64>().ok()) != Some(size)
        || decode(lines.next().ok_or("missing checkpoint root")?)? != current
        || lines.next().is_some()
    {
        return Err("Rekor checkpoint does not match proof".into());
    }
    let signed = format!("{text}\n");
    let mut valid = false;
    for line in signatures.lines() {
        let Some(rest) = line.strip_prefix("— ") else {
            return Err("invalid checkpoint signature line".into());
        };
        let (_, encoded) = rest.split_once(' ').ok_or("invalid checkpoint signature")?;
        let sig = decode(encoded)?;
        if sig.len() > 4
            && sig[..4] == log_id[..4]
            && verify_signature(key, details, signed.as_bytes(), &sig[4..]).is_ok()
        {
            valid = true;
            break;
        }
    }
    if !valid {
        return Err("invalid Rekor checkpoint signature".into());
    }
    Ok(())
}

pub(crate) fn verify_rekor(
    entry: &Value,
    envelope: &Value,
    certificate_der: &[u8],
    trusted_root: &Value,
) -> Result<i64, String> {
    let body_base64 = field(entry, "canonicalizedBody")?;
    let body = decode(body_base64)?;
    let parsed: Value = serde_json::from_slice(&body).map_err(|_| "invalid Rekor body")?;
    if field(&entry["kindVersion"], "kind")? != "dsse"
        || field(&entry["kindVersion"], "version")? != "0.0.1"
    {
        return Err("unsupported Rekor kind/version".into());
    }
    verify_binding(&parsed, envelope, certificate_der)?;
    let id = decode(field(&entry["logId"], "keyId")?)?;
    if id.len() != 32 {
        return Err("invalid Rekor log ID".into());
    }
    let logs = trusted_root["tlogs"]
        .as_array()
        .ok_or("missing trusted Rekor logs")?;
    let log = logs
        .iter()
        .find(|log| {
            log["logId"]["keyId"]
                .as_str()
                .and_then(|s| decode(s).ok())
                .as_deref()
                == Some(id.as_slice())
        })
        .ok_or("untrusted Rekor log")?;
    if field(log, "hashAlgorithm")? != "SHA2_256" {
        return Err("unsupported Rekor hash".into());
    }
    let key = decode(field(&log["publicKey"], "rawBytes")?)?;
    if digest::digest(&digest::SHA256, &key).as_ref() != id {
        return Err("Rekor key ID mismatch".into());
    }
    let details = field(&log["publicKey"], "keyDetails")?;
    let integrated = number(entry, "integratedTime")?;
    let valid = &log["publicKey"]["validFor"];
    if integrated == 0
        || integrated < time(field(valid, "start")?)?
        || (valid.get("end").is_some() && integrated > time(field(valid, "end")?)?)
    {
        return Err("Rekor key not valid at integrated time".into());
    }
    let index = number(entry, "logIndex")?;
    let payload = json!({"body": body_base64, "integratedTime": integrated, "logIndex": index, "logID": hex(&id)});
    let payload =
        serde_json_canonicalizer::to_vec(&payload).map_err(|_| "invalid Rekor SET payload")?;
    let set = decode(field(&entry["inclusionPromise"], "signedEntryTimestamp")?)?;
    verify_signature(&key, details, &payload, &set)?;
    let proof = entry
        .get("inclusionProof")
        .ok_or("missing Rekor inclusion proof")?;
    verify_proof(proof, &body, &key, details, &id)?;
    Ok(integrated as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_fixture_and_rejects_tampering() {
        let bundle: Value =
            serde_json::from_str(include_str!("sigstore_bundle_fixture.json")).unwrap();
        let root: Value = serde_json::from_str(include_str!("sigstore_trusted_root.json")).unwrap();
        let cert = decode(
            bundle["verificationMaterial"]["certificate"]["rawBytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut entry = bundle["verificationMaterial"]["tlogEntries"][0].clone();
        let envelope = &bundle["dsseEnvelope"];
        assert!(verify_rekor(&entry, envelope, &cert, &root).is_ok());
        let mut missing_proof = entry.clone();
        missing_proof
            .as_object_mut()
            .unwrap()
            .remove("inclusionProof");
        assert_eq!(
            verify_rekor(&missing_proof, envelope, &cert, &root).unwrap_err(),
            "missing Rekor inclusion proof"
        );
        let checkpoint = entry["inclusionProof"]["checkpoint"]["envelope"]
            .as_str()
            .unwrap();
        let (text, signature) = checkpoint.split_once("\n\n").unwrap();
        let mut many_signatures = entry.clone();
        many_signatures["inclusionProof"]["checkpoint"]["envelope"] =
            json!(format!("{text}\n\n{}", signature.repeat(8)));
        assert!(verify_rekor(&many_signatures, envelope, &cert, &root).is_ok());
        many_signatures["inclusionProof"]["checkpoint"]["envelope"] =
            json!(format!("{text}\n\n{}", signature.repeat(9)));
        assert_eq!(
            verify_rekor(&many_signatures, envelope, &cert, &root).unwrap_err(),
            "too many Rekor checkpoint signature lines"
        );
        many_signatures["inclusionProof"]["checkpoint"]["envelope"] = json!(format!(
            "{text}\n\n{}{signature}",
            "— test AAAA\n".repeat(8)
        ));
        assert_eq!(
            verify_rekor(&many_signatures, envelope, &cert, &root).unwrap_err(),
            "too many Rekor checkpoint signature lines"
        );
        let mut altered = entry.clone();
        altered["integratedTime"] = json!("1793201576");
        assert!(verify_rekor(&altered, envelope, &cert, &root).is_err());
        altered = entry.clone();
        altered["inclusionProof"]["rootHash"] = json!(STANDARD.encode([0u8; 32]));
        assert!(verify_rekor(&altered, envelope, &cert, &root).is_err());
        altered = entry.clone();
        altered["inclusionProof"]["checkpoint"]["envelope"] = json!("invalid");
        assert!(verify_rekor(&altered, envelope, &cert, &root).is_err());
        let mut altered_envelope = envelope.clone();
        altered_envelope["signatures"][0]["sig"] = json!(STANDARD.encode([0u8; 64]));
        assert!(verify_rekor(&entry, &altered_envelope, &cert, &root).is_err());
        entry["logIndex"] = json!("3542076399");
        assert!(verify_rekor(&entry, envelope, &cert, &root).is_err());
    }
}
