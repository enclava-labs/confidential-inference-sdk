use crate::{
    certificate_spki_sha256_hex, decode_tinfoil_attestation_body, sha256_digest, AttestationError,
    PpqEhbpLiveEvidence, Result, TinfoilAttestationDoc, TinfoilAttestationFormat,
};
use base64::Engine;
use serde::Deserialize;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPpqEvidence {
    pub quote: Vec<u8>,
    pub format: TinfoilAttestationFormat,
    pub enclave_certificate_der: Vec<u8>,
    pub spki: String,
    pub hpke_public_key: [u8; 32],
    pub domain: String,
    pub vcek: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    domain: String,
    enclave_attestation_report: TinfoilAttestationDoc,
    enclave_cert: String,
    #[serde(default)]
    vcek: Option<String>,
}
/// Verify the quote and both halves of its report-data binding.
pub fn verify_ppq_ehbp_quote(
    capture: &PpqEhbpLiveEvidence,
    parsed: &ParsedPpqEvidence,
    verifier: &dyn crate::TinfoilQuoteVerifier,
) -> Result<crate::VerifiedTinfoilQuote> {
    if !certificate_spki_sha256_hex(&parsed.enclave_certificate_der)?
        .eq_ignore_ascii_case(&parsed.spki)
    {
        return Err(invalid("PPQ certificate SPKI does not match parsed SPKI"));
    }
    let synthetic = crate::TinfoilLiveCaptureEvidence {
        schema: crate::TinfoilLiveCaptureEvidence::SCHEMA.into(),
        provider: capture.provider.clone(),
        route_id: capture.route_id.clone(),
        evidence_family: capture.evidence_family.clone(),
        requested_model: capture.requested_model.clone(),
        policy_digest: capture.policy_digest.clone(),
        nonce: None,
        evidence_endpoint: capture.evidence_endpoint.clone(),
        live_tls_spki_sha256: parsed.spki.clone(),
        live_tls_leaf_certificate_der_base64: base64::engine::general_purpose::STANDARD
            .encode(&parsed.enclave_certificate_der),
        raw_attestation_body_base64: String::new(),
    };
    let verified = verifier.verify_tinfoil_quote(&crate::TinfoilQuoteVerificationRequest {
        capture: &synthetic,
        attestation_format: parsed.format,
        quote_bytes: &parsed.quote,
        live_tls_leaf_certificate_der: &parsed.enclave_certificate_der,
        live_tls_spki_sha256: &parsed.spki,
    })?;
    if verified.attestation_format != parsed.format.as_str()
        || verified.hardware.cpu != parsed.format.cpu_kind()
    {
        return Err(invalid(
            "PPQ quote verifier returned the wrong format or hardware",
        ));
    }
    let expected = format!(
        "{}{}",
        parsed.spki,
        parsed
            .hpke_public_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    if !verified.report_data.eq_ignore_ascii_case(&expected) {
        return Err(invalid(
            "PPQ quote report_data does not bind certificate SPKI and HPKE key",
        ));
    }
    Ok(verified)
}

fn invalid(message: impl Into<String>) -> AttestationError {
    AttestationError::InvalidEvidence(message.into())
}

/// Parse and authenticate the certificate's attestation-document and HPKE SANs.
/// Hardware authenticity and the report-data binding require quote verification.
pub fn parse_ppq_ehbp_evidence(capture: &PpqEhbpLiveEvidence) -> Result<ParsedPpqEvidence> {
    if capture.schema != PpqEhbpLiveEvidence::SCHEMA {
        return Err(invalid("unsupported PPQ evidence schema"));
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&capture.raw_bundle_base64)
        .map_err(|e| invalid(format!("invalid PPQ bundle base64: {e}")))?;
    if raw.len() > 4 * 1024 * 1024 {
        return Err(invalid("PPQ bundle too large"));
    }
    let bundle: Bundle = serde_json::from_slice(&raw)?;
    let doc = &bundle.enclave_attestation_report;
    let format = TinfoilAttestationFormat::parse(&doc.format)?;
    let quote = decode_tinfoil_attestation_body(&doc.body)?;
    match format {
        TinfoilAttestationFormat::SevSnpGuestV2 if quote.len() != 1184 => {
            return Err(invalid("invalid PPQ SNP report length"))
        }
        TinfoilAttestationFormat::TdxGuestV2 if quote.len() < 48 => {
            return Err(invalid("invalid PPQ TDX quote length"))
        }
        _ => {}
    }
    let pem = bundle.enclave_cert.trim();
    let encoded = pem
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|s| s.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or_else(|| invalid("invalid PPQ certificate PEM"))?;
    let enclave_certificate_der = base64::engine::general_purpose::STANDARD
        .decode(
            encoded
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<String>(),
        )
        .map_err(|e| invalid(format!("invalid PPQ certificate PEM: {e}")))?;
    let cert = x509_cert::Certificate::from_der(&enclave_certificate_der)
        .map_err(|e| AttestationError::InvalidCertificate(e.to_string()))?;
    let mut san = None;
    for ext in cert.tbs_certificate().extensions().into_iter().flatten() {
        if ext.extn_id.to_string() == "2.5.29.17" {
            if san.is_some() {
                return Err(invalid("duplicate certificate SAN extension"));
            }
            san = Some(
                SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| AttestationError::InvalidCertificate(e.to_string()))?,
            );
        }
    }
    let san = san.ok_or_else(|| invalid("PPQ certificate has no SAN"))?;
    let names: Vec<&str> = san
        .0
        .iter()
        .filter_map(|name| match name {
            GeneralName::DnsName(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    if bundle.domain.is_empty() || !names.iter().any(|name| dns_matches(name, &bundle.domain)) {
        return Err(invalid("PPQ certificate domain mismatch"));
    }
    let hpke_public_key: [u8; 32] = decode_domains(&names, "hpke")?
        .try_into()
        .map_err(|_| invalid("PPQ HPKE key must be 32 bytes"))?;
    let hash = sha256_digest(format!("{}{}", doc.format, doc.body).as_bytes());
    if decode_domains(&names, "hatt")? != hash.trim_start_matches("sha256:").as_bytes() {
        return Err(invalid("PPQ certificate attestation hash mismatch"));
    }
    let spki = certificate_spki_sha256_hex(&enclave_certificate_der)?;
    let vcek = base64::engine::general_purpose::STANDARD
        .decode(bundle.vcek.as_deref().unwrap_or(""))
        .map_err(|e| invalid(format!("invalid PPQ VCEK: {e}")))?;
    if format == TinfoilAttestationFormat::SevSnpGuestV2 && vcek.is_empty() {
        return Err(invalid("empty PPQ VCEK"));
    }
    Ok(ParsedPpqEvidence {
        quote,
        format,
        enclave_certificate_der,
        spki,
        hpke_public_key,
        domain: bundle.domain,
        vcek,
    })
}

fn dns_matches(pattern: &str, domain: &str) -> bool {
    if pattern.eq_ignore_ascii_case(domain) {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if let Some((label, rest)) = domain.split_once('.') {
            return !label.is_empty() && rest.eq_ignore_ascii_case(suffix);
        }
    }
    false
}

fn decode_domains(names: &[&str], prefix: &str) -> Result<Vec<u8>> {
    let mut chunks = Vec::new();
    for name in names {
        let mut parts = name.split('.');
        let first = parts.next().unwrap_or("");
        if !parts
            .next()
            .is_some_and(|part| part.eq_ignore_ascii_case(prefix))
        {
            continue;
        }
        let bytes = first.as_bytes();
        if bytes.len() < 3 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
            return Err(invalid("invalid PPQ SAN chunk index"));
        }
        chunks.push(((bytes[0] - b'0') * 10 + bytes[1] - b'0', &bytes[2..]));
    }
    chunks.sort_by_key(|chunk| chunk.0);
    if chunks.is_empty()
        || chunks
            .iter()
            .enumerate()
            .any(|(i, c)| usize::from(c.0) != i)
    {
        return Err(invalid("missing or duplicate PPQ SAN chunks"));
    }
    let mut output = Vec::new();
    let mut bits = 0u32;
    let mut count = 0;
    for &(_, chunk) in &chunks {
        for &byte in chunk {
            let value = match byte.to_ascii_uppercase() {
                b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
                b'2'..=b'7' => byte - b'2' + 26,
                _ => return Err(invalid("invalid PPQ SAN base32")),
            };
            bits = (bits << 5) | u32::from(value);
            count += 5;
            if count >= 8 {
                count -= 8;
                output.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
    }
    if count >= 5 || bits != 0 {
        return Err(invalid("invalid PPQ SAN base32 padding"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn capture(bundle: &serde_json::Value) -> PpqEhbpLiveEvidence {
        PpqEhbpLiveEvidence {
            schema: PpqEhbpLiveEvidence::SCHEMA.into(),
            provider: "ppq".into(),
            route_id: "route".into(),
            evidence_family: "ppq_ehbp".into(),
            requested_model: "model".into(),
            policy_digest: "policy".into(),
            evidence_endpoint: "endpoint".into(),
            raw_bundle_base64: base64::engine::general_purpose::STANDARD.encode(bundle.to_string()),
        }
    }

    struct Quote(String);
    impl crate::TinfoilQuoteVerifier for Quote {
        fn verify_tinfoil_quote(
            &self,
            _: &crate::TinfoilQuoteVerificationRequest<'_>,
        ) -> Result<crate::VerifiedTinfoilQuote> {
            Ok(crate::VerifiedTinfoilQuote::from_verified_quote(
                TinfoilAttestationFormat::SevSnpGuestV2,
                crate::EvidenceHardware {
                    cpu: crate::CpuTeeKind::SevSnp,
                    gpu: None,
                },
                "measurement",
                &self.0,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z",
                0,
            ))
        }
    }

    #[test]
    fn bundle_and_quote_bindings_fail_closed() {
        let bundle: serde_json::Value =
            serde_json::from_str(include_str!("ppq_test_bundle.json")).unwrap();
        let evidence = capture(&bundle);
        let parsed = parse_ppq_ehbp_evidence(&evidence).unwrap();
        let report_data = format!(
            "{}{}",
            parsed.spki,
            parsed
                .hpke_public_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert!(verify_ppq_ehbp_quote(&evidence, &parsed, &Quote(report_data.clone())).is_ok());
        let mut wrong_key = parsed.clone();
        wrong_key.hpke_public_key[0] ^= 1;
        assert!(verify_ppq_ehbp_quote(&evidence, &wrong_key, &Quote(report_data)).is_err());
        assert!(verify_ppq_ehbp_quote(&evidence, &parsed, &Quote("00".repeat(64))).is_err());
        assert!(
            verify_ppq_ehbp_quote(&evidence, &parsed, &crate::FailClosedTinfoilQuoteVerifier)
                .is_err()
        );
        let mut wrong_domain = bundle.clone();
        wrong_domain["domain"] = "wrong.example".into();
        assert!(parse_ppq_ehbp_evidence(&capture(&wrong_domain)).is_err());
        let mut wrong_report = bundle.clone();
        wrong_report["enclaveAttestationReport"]["body"] = "".into();
        assert!(parse_ppq_ehbp_evidence(&capture(&wrong_report)).is_err());
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![0; 1184]).unwrap();
        let mut wrong_hatt = bundle.clone();
        wrong_hatt["enclaveAttestationReport"]["body"] = base64::engine::general_purpose::STANDARD
            .encode(encoder.finish().unwrap())
            .into();
        assert!(parse_ppq_ehbp_evidence(&capture(&wrong_hatt)).is_err());
        let mut wrong_vcek = bundle;
        wrong_vcek["vcek"] = "".into();
        assert!(parse_ppq_ehbp_evidence(&capture(&wrong_vcek)).is_err());
    }

    #[test]
    fn rejects_bad_san_chunks_and_domains() {
        assert_eq!(
            decode_domains(&["00mzxw6.hpke.example"], "hpke").unwrap(),
            b"foo"
        );
        assert!(decode_domains(&["01mzxw6.hpke.example"], "hpke").is_err());
        assert!(decode_domains(&["00mzxw6.hpke.example", "00mzxw6.hpke.example"], "hpke").is_err());
        assert!(decode_domains(&["00mz.hpke.example"], "hpke").is_err());
        assert!(dns_matches("*.example.com", "a.example.com"));
        assert!(!dns_matches("*.example.com", "a.b.example.com"));
    }
}
