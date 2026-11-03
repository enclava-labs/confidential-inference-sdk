use crate::{AttestationError, CpuTeeKind, Result, VerifiedTinfoilQuote};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1};
use serde_json::Value;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{
    name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName,
};
use x509_cert::Certificate;

fn invalid(message: impl Into<String>) -> AttestationError {
    AttestationError::InvalidEvidence(format!("Sigstore: {}", message.into()))
}

fn bytes(value: &Value) -> Result<Vec<u8>> {
    STANDARD
        .decode(
            value
                .as_str()
                .ok_or_else(|| invalid("missing base64 field"))?,
        )
        .map_err(|_| invalid("invalid base64 field"))
}

fn certificate(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|e| invalid(format!("invalid certificate: {e}")))
}

fn check_time(cert: &Certificate, time: i64) -> Result<()> {
    let validity = cert.tbs_certificate().validity();
    if time < 0
        || (time as u64) < validity.not_before.to_unix_duration().as_secs()
        || (time as u64) > validity.not_after.to_unix_duration().as_secs()
    {
        return Err(invalid("certificate is not valid at integrated time"));
    }
    Ok(())
}

fn check_issued(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    if cert.tbs_certificate().issuer() != issuer.tbs_certificate().subject()
        || cert.signature_algorithm() != cert.tbs_certificate().signature()
        || cert.signature_algorithm().oid.to_string() != "1.2.840.10045.4.3.3"
    {
        return Err(invalid(
            "certificate issuer or signature algorithm mismatch",
        ));
    }
    let key = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| invalid("invalid issuer public key"))?;
    let signature = cert
        .signature()
        .as_bytes()
        .ok_or_else(|| invalid("invalid certificate signature"))?;
    let tbs = cert
        .tbs_certificate()
        .to_der()
        .map_err(|_| invalid("invalid certificate encoding"))?;
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, key)
        .verify(&tbs, signature)
        .map_err(|_| invalid("certificate signature mismatch"))
}

fn extension<'a>(cert: &'a Certificate, oid: &str) -> Result<Option<&'a [u8]>> {
    let mut found = None;
    for ext in cert.tbs_certificate().extensions().into_iter().flatten() {
        if ext.extn_id.to_string() == oid {
            if found.is_some() {
                return Err(invalid("duplicate certificate extension"));
            }
            found = Some(ext.extn_value.as_bytes());
        }
    }
    Ok(found)
}

fn required_extension<'a>(cert: &'a Certificate, oid: &str) -> Result<&'a [u8]> {
    extension(cert, oid)?.ok_or_else(|| invalid(format!("missing certificate extension {oid}")))
}

fn utf8_extension(value: &[u8]) -> Result<&str> {
    let s = x509_cert::der::asn1::Utf8StringRef::from_der(value)
        .map_err(|_| invalid("invalid Fulcio UTF8 extension"))?;
    Ok(s.as_str())
}

fn check_identity(cert: &Certificate, repo: &str) -> Result<()> {
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| invalid("invalid repository"))?;
    if owner.is_empty()
        || name.is_empty()
        || !repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
        || name.contains('/')
    {
        return Err(invalid("invalid repository"));
    }
    let extensions = cert
        .tbs_certificate()
        .extensions()
        .ok_or_else(|| invalid("missing certificate extensions"))?;
    let mut seen = std::collections::HashSet::new();
    for ext in extensions {
        let oid = ext.extn_id.to_string();
        if !seen.insert(oid.clone()) {
            return Err(invalid("duplicate certificate extension"));
        }
        if ext.critical
            && !matches!(
                oid.as_str(),
                "2.5.29.15" | "2.5.29.17" | "2.5.29.19" | "2.5.29.37"
            )
        {
            return Err(invalid("unrecognized critical certificate extension"));
        }
    }
    let eku = ExtendedKeyUsage::from_der(required_extension(cert, "2.5.29.37")?)
        .map_err(|_| invalid("invalid extended key usage"))?;
    if !eku
        .0
        .iter()
        .any(|oid| oid.to_string() == "1.3.6.1.5.5.7.3.3")
    {
        return Err(invalid("certificate is not valid for code signing"));
    }
    let usage = KeyUsage::from_der(required_extension(cert, "2.5.29.15")?)
        .map_err(|_| invalid("invalid key usage"))?;
    if !usage.digital_signature() {
        return Err(invalid("certificate cannot sign"));
    }
    if let Some(value) = extension(cert, "2.5.29.19")? {
        if BasicConstraints::from_der(value)
            .map_err(|_| invalid("invalid basic constraints"))?
            .ca
        {
            return Err(invalid("signer is a CA"));
        }
    }
    let san = SubjectAltName::from_der(required_extension(cert, "2.5.29.17")?)
        .map_err(|_| invalid("invalid SAN"))?;
    let prefix = format!("https://github.com/{repo}/.github/workflows/");
    let matches = san.0.iter().any(|name| match name {
        GeneralName::UniformResourceIdentifier(uri) => uri
            .as_str()
            .strip_prefix(prefix.as_str())
            .and_then(|s| s.split_once('@'))
            .is_some_and(|(workflow, reference)| {
                !workflow.is_empty()
                    && reference
                        .strip_prefix("refs/tags/")
                        .is_some_and(|tag| !tag.is_empty())
            }),
        _ => false,
    });
    if !matches {
        return Err(invalid("certificate workflow identity mismatch"));
    }
    let issuer = "https://token.actions.githubusercontent.com";
    let mut found_issuer = false;
    if let Some(value) = extension(cert, "1.3.6.1.4.1.57264.1.1")? {
        if value != issuer.as_bytes() {
            return Err(invalid("OIDC issuer mismatch"));
        }
        found_issuer = true;
    }
    if let Some(value) = extension(cert, "1.3.6.1.4.1.57264.1.8")? {
        if utf8_extension(value)? != issuer {
            return Err(invalid("OIDC issuer mismatch"));
        }
        found_issuer = true;
    }
    if !found_issuer {
        return Err(invalid("missing OIDC issuer"));
    }
    let mut found_repo = false;
    if let Some(value) = extension(cert, "1.3.6.1.4.1.57264.1.5")? {
        if value != repo.as_bytes() {
            return Err(invalid("source repository mismatch"));
        }
        found_repo = true;
    }
    if let Some(value) = extension(cert, "1.3.6.1.4.1.57264.1.12")? {
        if utf8_extension(value)? != format!("https://github.com/{repo}") {
            return Err(invalid("source repository mismatch"));
        }
        found_repo = true;
    }
    if !found_repo {
        return Err(invalid("missing source repository"));
    }
    if !utf8_extension(required_extension(cert, "1.3.6.1.4.1.57264.1.14")?)?
        .strip_prefix("refs/tags/")
        .is_some_and(|tag| !tag.is_empty())
    {
        return Err(invalid("source repository ref is not a tag"));
    }
    Ok(())
}

fn verify_chain(leaf: &Certificate, time: i64, root: &Value) -> Result<Vec<u8>> {
    let authorities = root["certificateAuthorities"]
        .as_array()
        .ok_or_else(|| invalid("invalid trusted root"))?;
    let time_ns =
        u128::try_from(time).map_err(|_| invalid("invalid integrated time"))? * 1_000_000_000;
    for authority in authorities {
        let start = authority
            .pointer("/validFor/start")
            .and_then(Value::as_str)
            .and_then(crate::sigstore_sct::timestamp_ns)
            .ok_or_else(|| invalid("invalid trusted CA validity start"))?;
        let end = authority
            .pointer("/validFor/end")
            .map(|value| {
                value
                    .as_str()
                    .and_then(crate::sigstore_sct::timestamp_ns)
                    .ok_or_else(|| invalid("invalid trusted CA validity end"))
            })
            .transpose()?;
        if end.is_some_and(|end| end < start) {
            return Err(invalid("invalid trusted CA validity range"));
        }
        if time_ns < start || end.is_some_and(|end| time_ns > end) {
            continue;
        }
        let chain = authority["certChain"]["certificates"]
            .as_array()
            .ok_or_else(|| invalid("invalid trusted CA chain"))?;
        if chain.is_empty() {
            continue;
        }
        let ders: Vec<Vec<u8>> = chain
            .iter()
            .map(|c| bytes(&c["rawBytes"]))
            .collect::<Result<_>>()?;
        let certs: Vec<Certificate> = ders.iter().map(|d| certificate(d)).collect::<Result<_>>()?;
        if check_time(leaf, time).is_err() || check_issued(leaf, &certs[0]).is_err() {
            continue;
        }
        if certs.iter().any(|cert| check_time(cert, time).is_err()) {
            continue;
        }
        if certs
            .windows(2)
            .any(|pair| check_issued(&pair[0], &pair[1]).is_err())
        {
            continue;
        }
        return Ok(ders[0].clone());
    }
    Err(invalid("no trusted Fulcio certificate chain"))
}

/// Verify a Sigstore bundle offline and return its signed SNP measurement.
pub fn verify_tinfoil_sigstore_bundle(bundle: &Value, repo: &str, digest: &str) -> Result<String> {
    if bundle["mediaType"].as_str() != Some("application/vnd.dev.sigstore.bundle.v0.3+json") {
        return Err(invalid("unsupported bundle media type"));
    }
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("invalid artifact SHA-256"));
    }
    let root: Value = serde_json::from_str(include_str!("sigstore_trusted_root.json"))?;
    let envelope = &bundle["dsseEnvelope"];
    let leaf_der = bytes(&bundle["verificationMaterial"]["certificate"]["rawBytes"])?;
    let leaf = certificate(&leaf_der)?;
    let entries = bundle["verificationMaterial"]["tlogEntries"]
        .as_array()
        .ok_or_else(|| invalid("missing transparency log"))?;
    if entries.len() != 1 {
        return Err(invalid("expected exactly one transparency entry"));
    }
    let time = crate::sigstore_rekor::verify_rekor(&entries[0], envelope, &leaf_der, &root)
        .map_err(invalid)?;
    let issuer_der = verify_chain(&leaf, time, &root)?;
    check_identity(&leaf, repo)?;
    crate::sigstore_sct::verify_sct(&leaf_der, &issuer_der, &root).map_err(invalid)?;
    let payload_type = envelope["payloadType"]
        .as_str()
        .ok_or_else(|| invalid("missing DSSE payload type"))?;
    if payload_type != "application/vnd.in-toto+json" {
        return Err(invalid("unexpected DSSE payload type"));
    }
    let payload = bytes(&envelope["payload"])?;
    let signatures = envelope["signatures"]
        .as_array()
        .ok_or_else(|| invalid("missing DSSE signature"))?;
    if signatures.len() != 1 {
        return Err(invalid("expected exactly one DSSE signature"));
    }
    let signature = bytes(&signatures[0]["sig"])?;
    let mut pae = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    pae.extend_from_slice(&payload);
    let spki = leaf.tbs_certificate().subject_public_key_info();
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| invalid("invalid signer public key"))?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
        .verify(&pae, &signature)
        .map_err(|_| invalid("invalid DSSE signature"))?;
    let statement: Value = serde_json::from_slice(&payload)?;
    if statement["_type"] != "https://in-toto.io/Statement/v1"
        || statement["predicateType"] != "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
    {
        return Err(invalid("unsupported attestation statement"));
    }
    let subjects = statement["subject"]
        .as_array()
        .ok_or_else(|| invalid("missing subjects"))?;
    if !subjects.iter().any(|subject| {
        subject["digest"]["sha256"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case(digest))
    }) {
        return Err(invalid("artifact digest mismatch"));
    }
    let predicate = &statement["predicate"];
    for name in ["rtmr1", "rtmr2"] {
        if !predicate["tdx_measurement"][name].is_string() {
            return Err(invalid("invalid TDX measurement"));
        }
    }
    let measurement = predicate["snp_measurement"]
        .as_str()
        .ok_or_else(|| invalid("missing SNP measurement"))?;
    if measurement.len() != 96 || !measurement.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("invalid SNP measurement"));
    }
    Ok(measurement.to_ascii_lowercase())
}

/// Bind a signed SNP release measurement to an already verified hardware quote.
pub fn verify_tinfoil_release_measurement(
    measurement: &str,
    quote: &VerifiedTinfoilQuote,
) -> Result<()> {
    if quote.hardware.cpu != CpuTeeKind::SevSnp
        || quote.attestation_format != crate::TINFOIL_SEV_SNP_GUEST_V2_FORMAT
    {
        return Err(invalid("release measurement requires an SNP quote"));
    }
    if measurement.len() != 96 || !measurement.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("invalid SNP release measurement"));
    }
    let actual = quote
        .tee_measurement
        .strip_prefix("sev-snp:measurement:")
        .ok_or_else(|| invalid("invalid quote measurement"))?;
    if !actual.eq_ignore_ascii_case(measurement) {
        return Err(invalid("quote measurement differs from release"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceHardware, TinfoilAttestationFormat};

    const REPO: &str = "tinfoilsh/confidential-model-router";
    const DIGEST: &str = "adc71cdb94b8762993777156f3290463f3a8ee2ea42665289a83d502cdf69d76";
    const MEASUREMENT: &str = "e716274321b31eaf1301d3eddfbe477da1a69c6a8afeea9f8cd36b6546d94728ffb88b4eb11f0a4cc76e40e3b294b8a7";

    fn bundle() -> Value {
        serde_json::from_str(include_str!("sigstore_bundle_fixture.json")).unwrap()
    }

    #[test]
    fn captured_ppq_bundle_and_trusted_root() {
        let ppq: Value =
            serde_json::from_str(include_str!("sigstore_ppq_bundle_fixture.json")).unwrap();
        assert_eq!(
            verify_tinfoil_sigstore_bundle(&ppq, REPO, DIGEST).unwrap(),
            MEASUREMENT
        );
        assert_eq!(
            crate::sha256_digest(include_bytes!("sigstore_trusted_root.json")),
            "sha256:6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
        );
    }

    #[test]
    fn real_bundle_and_adversarial_inputs() {
        let good = bundle();
        assert_eq!(
            verify_tinfoil_sigstore_bundle(&good, REPO, DIGEST).unwrap(),
            MEASUREMENT
        );
        assert!(verify_tinfoil_sigstore_bundle(&good, "attacker/repo", DIGEST).is_err());
        assert!(verify_tinfoil_sigstore_bundle(&good, REPO, &"0".repeat(64)).is_err());
        for pointer in [
            "/dsseEnvelope/payload",
            "/dsseEnvelope/signatures/0/sig",
            "/verificationMaterial/certificate/rawBytes",
            "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
            "/verificationMaterial/tlogEntries/0/canonicalizedBody",
            "/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
            "/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::String("invalid".into());
            assert!(
                verify_tinfoil_sigstore_bundle(&bad, REPO, DIGEST).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_bundle_media_types() {
        let good = bundle();
        for value in [
            Value::Null,
            serde_json::json!("application/vnd.dev.sigstore.bundle.v0.2+json"),
        ] {
            let mut bad = good.clone();
            bad["mediaType"] = value;
            assert!(verify_tinfoil_sigstore_bundle(&bad, REPO, DIGEST).is_err());
        }
    }

    #[test]
    fn rejects_branch_spoof_and_invalid_source_ref() {
        let der = bytes(&bundle()["verificationMaterial"]["certificate"]["rawBytes"]).unwrap();
        let leaf = certificate(&der).unwrap();
        assert!(check_identity(&leaf, REPO).is_ok());

        let old = b"tinfoil-release-publish.yml@refs/tags/v0.0.168";
        let mut spoof = vec![b'x'; old.len() - b"@refs/heads/x@refs/tags/v1".len()];
        spoof.extend_from_slice(b"@refs/heads/x@refs/tags/v1");
        let mut bad = der.clone();
        let pos = bad.windows(old.len()).position(|v| v == old).unwrap();
        let mut other_workflow = der.clone();
        other_workflow[pos] = b'x';
        assert!(check_identity(&certificate(&other_workflow).unwrap(), REPO).is_ok());
        bad[pos..pos + old.len()].copy_from_slice(&spoof);
        assert!(check_identity(&certificate(&bad).unwrap(), REPO).is_err());

        let oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x83\xbf\x30\x01\x0e";
        let pos = der.windows(oid.len()).position(|v| v == oid).unwrap();
        let mut missing = der.clone();
        missing[pos + oid.len() - 1] = 0x7e;
        assert!(check_identity(&certificate(&missing).unwrap(), REPO).is_err());

        let value = required_extension(&leaf, "1.3.6.1.4.1.57264.1.14").unwrap();
        let value_pos = der.windows(value.len()).position(|v| v == value).unwrap();
        let mut malformed = der.clone();
        malformed[value_pos] = 0x16;
        assert!(check_identity(&certificate(&malformed).unwrap(), REPO).is_err());
        let mut wrong = der.clone();
        let tag = b"refs/tags/";
        let tag_pos = value.windows(tag.len()).position(|v| v == tag).unwrap();
        wrong[value_pos + tag_pos..value_pos + tag_pos + tag.len()].copy_from_slice(b"refs/fake/");
        assert!(check_identity(&certificate(&wrong).unwrap(), REPO).is_err());
    }

    #[test]
    fn ca_windows_follow_authorities_and_preserve_boundaries() {
        let leaf = certificate(
            &bytes(&bundle()["verificationMaterial"]["certificate"]["rawBytes"]).unwrap(),
        )
        .unwrap();
        let root: Value = serde_json::from_str(include_str!("sigstore_trusted_root.json")).unwrap();
        let time = 1_793_201_575;
        assert!(verify_chain(&leaf, time, &root).is_ok());

        let mut reordered = root.clone();
        reordered["certificateAuthorities"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(verify_chain(&leaf, time, &reordered).is_ok());

        let mut extended = root.clone();
        let authorities = extended["certificateAuthorities"].as_array_mut().unwrap();
        let mut signer = authorities[1].clone();
        authorities[1] = authorities[0].clone();
        signer["validFor"]["start"] = serde_json::json!("2026-10-28T15:32:55.000000001Z");
        authorities.push(signer);
        assert!(verify_chain(&leaf, time, &extended).is_err());
        extended["certificateAuthorities"][2]["validFor"]["start"] =
            serde_json::json!("2026-10-28T15:32:55Z");
        extended["certificateAuthorities"][2]["validFor"]["end"] =
            serde_json::json!("2026-10-28T15:32:55Z");
        assert!(verify_chain(&leaf, time, &extended).is_ok());
        extended["certificateAuthorities"][2]["validFor"]["end"] =
            serde_json::json!("2026-10-28T15:32:54.999999999Z");
        assert!(verify_chain(&leaf, time, &extended).is_err());
        extended["certificateAuthorities"][2]["validFor"]["end"] = serde_json::json!("invalid");
        assert!(verify_chain(&leaf, time, &extended).is_err());
        extended["certificateAuthorities"][2]["validFor"]["end"] =
            serde_json::json!("2026-10-28T15:32:55Z");
        extended["certificateAuthorities"][2]["validFor"]["start"] = serde_json::json!("invalid");
        assert!(verify_chain(&leaf, time, &extended).is_err());
    }

    #[test]
    fn rejects_wrong_oidc_issuer_and_expired_certificate() {
        let good = bundle();
        let mut der = bytes(&good["verificationMaterial"]["certificate"]["rawBytes"]).unwrap();
        let leaf = certificate(&der).unwrap();
        assert!(check_time(&leaf, 1).is_err());
        assert!(check_time(&leaf, 1_793_201_575).is_ok());
        let issuer = b"https://token.actions.githubusercontent.com";
        let position = der
            .windows(issuer.len())
            .position(|bytes| bytes == issuer)
            .unwrap();
        der[position] = b'x';
        let altered = certificate(&der).unwrap();
        assert!(check_identity(&altered, REPO).is_err());
    }

    #[test]
    fn release_measurement_requires_matching_snp_quote() {
        let mut quote = VerifiedTinfoilQuote::from_verified_quote(
            TinfoilAttestationFormat::SevSnpGuestV2,
            EvidenceHardware {
                cpu: CpuTeeKind::SevSnp,
                gpu: None,
            },
            format!("sev-snp:measurement:{MEASUREMENT}"),
            "",
            "",
            "",
            0,
        );
        assert!(verify_tinfoil_release_measurement(MEASUREMENT, &quote).is_ok());
        assert!(verify_tinfoil_release_measurement(&"0".repeat(96), &quote).is_err());
        quote.hardware.cpu = CpuTeeKind::Tdx;
        assert!(verify_tinfoil_release_measurement(MEASUREMENT, &quote).is_err());
    }
}
