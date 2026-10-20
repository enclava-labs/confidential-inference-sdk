use crate::{
    format_utc_timestamp_millis, AttestationError, CpuTeeKind, EvidenceHardware, Result,
    TinfoilAttestationFormat, TinfoilQuoteVerificationRequest, TinfoilQuoteVerifier,
    VerifiedTinfoilQuote,
};
use base64::Engine;
use ring::signature::{
    RsaPublicKeyComponents, UnparsedPublicKey, ECDSA_P384_SHA384_FIXED, RSA_PSS_2048_8192_SHA384,
};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::der::{Decode, Encode};

const REPORT_LEN: usize = 1184;
const SIGNED_LEN: usize = 672;
const CHIP_ID: std::ops::Range<usize> = 416..480;
const REPORT_DATA: std::ops::Range<usize> = 80..144;
const MEASUREMENT: std::ops::Range<usize> = 144..192;
const REPORTED_TCB: std::ops::Range<usize> = 384..392;
const GENOA_ASK_DER_B64: &str = concat!(
    "MIIGiTCCBDigAwIBAgIDAgACMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAa",
    "BgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDASBgNVBAsMC0VuZ2lu",
    "ZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB",
    "MR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMRIwEAYDVQQDDAlBUkstR2Vub2Ew",
    "HhcNMjIxMDMxMTMzMzQ4WhcNNDcxMDMxMTMzMzQ4WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmlu",
    "ZzELMAkGA1UEBhMCVVMxFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0G",
    "A1UECgwWQWR2YW5jZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJU0VWLUdlbm9hMIICIjAN",
    "BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoHJhvk4Fwwkwb03AMfLySXJSXmEaCZMTRbLg",
    "Paj4oEzaD9tGfxCSw/nsCAiXHQaWUt++bnbjJO05TKT5d+Cdrz4/fiRBpbhf0xzvh11O+wJT",
    "BPj3uCzDm48vEZ8l5SXMO4wd/QqwsrejFERPD/Hdfv1mGCMW7ac0ug8trDzqGe+l+p8NMjp/",
    "EqBDY2vd8hLaVLmS+XjAqlYVNRksh9aTzSYL19/cTrBDmqQ2y8k23zNl2lW6q/BtQOpWGVs3",
    "EWvBHb/Qnf3f3S9+lC4H2jdDy9yn7kqyTWq4WCBnE4qhYJRokulYtzMZM1Ilk4Z6RPkOTR1M",
    "J4gdFtj7lKmrkSuOoJYmqhJIsQJ854lAbJybgU7zyzWAwu3uaslkYKUEAQf2ja5Hyl3IBqOz",
    "pqY31SpKzbl8NXveZybRMklwfe4iDLI25T9ku9CVetDYifCbdGeuHdTwZBBemW4NE57L7iEV",
    "8+zz8nxng8OMX//4pXntWqmQbEAnBLv2ToTgd1H2zYRthyDLc3V119/+FnTW17LK6bKzTCgE",
    "nCHQEcAt0hDQLLF799+2lZTxxfBEoduAZax6IjgAMCi6e1ZfKPJSkdvb2m3BwfP8bniG7+AE",
    "Jv1WOEmnBJc1pVQCttbJUodbi07Vfen5JRUqAvSM3ObWQOzSAGzsGnpIigwFpW6m9F7uYVUC",
    "AwEAAaOBozCBoDAdBgNVHQ4EFgQUssZ7pDW7HJVkHAmgQf/F3EmGFVowHwYDVR0jBBgwFoAU",
    "n135/g3Y81rQMxol74EpT74xqFswEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC",
    "AQQwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cHM6Ly9rZHNpbnRmLmFtZC5jb20vdmNlay92MS9H",
    "ZW5vYS9jcmwwRgYJKoZIhvcNAQEKMDmgDzANBglghkgBZQMEAgIFAKEcMBoGCSqGSIb3DQEB",
    "CDANBglghkgBZQMEAgIFAKIDAgEwowMCAQEDggIBAIgu3V2tQJOo0/6GvNmwLXbLDrsLKXqH",
    "UqdGyOZUpPHM3ujTaex1G+8bEgBswwBa+wNvl1SQqRqy2x2QwP+i//BcWr3lMrUxci4G7/P8",
    "hZBV821nrAUZtbvfqla5MrRH9AKJXWW/pmtd10czqCHkzdLQNZNjt2dnZHMQAMtGs1AtynRE",
    "HNwEBiH2KAt7gUc/sKWnSCipztKE76puN/XXbSx+Ws+VPiFw6CBAeI9dqnEiQ1tpEgqtWEtc",
    "Km7Ggb1XH6oWbISoowvc00/ADWfNom0xl6v2C6RIWYgUoZ2f7PCyV3Dtbu/fQfyyZvmtVLA4",
    "gB2Ehc6Omjy21Y55WY9IweHlKENMPEUVtRqOvRVI0ml9Wbalf049joCu2j33XPqwp3Irzevm",
    "PBDGpR2Stdm3K66a/g/BSY7Wc9/VeykP3RXlxY1TMMJ8F1lpg6Tmu+c+vow7cliyqOoayAnR",
    "71U8+rWrL3HRHheSVX8GPYOaDNBTt831Z027vDWv3811vMoxYxhuTRaokvNWCSzmJ2EWrPYH",
    "cHOtkjSFKN7ot0Rc70fIRZEYc2rb3ywLSicEq3JQCnnz6iCZ1tMfplzcrJ2LnW2F1C8yRV+o",
    "kylyORlsaxOLKYOWjaDTSFaq1NIwodHp7X9fOG48uRuJWS8GmifD969sC4Ut2FJFoklceBVU",
    "NCHR"
);
const GENOA_ARK_DER_B64: &str = concat!(
    "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",
    "0zf1c1salVuGFk2w/wMz1R1BHg=="
);
// SHA-256 of the AMD Genoa ARK DER in its published cert_chain; the test below pins this value.
const GENOA_ARK_SHA256: &str = "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1";

/// Tinfoil SEV-SNP verifier using a VCEK resolved by the provider layer.
///
/// The verifier is deliberately bound to the Genoa product supported by the
/// Tinfoil SEV-SNP v2 contract.
#[derive(Clone, Debug)]
pub struct SevSnpTinfoilQuoteVerifier {
    vcek_der: Vec<u8>,
}

impl SevSnpTinfoilQuoteVerifier {
    pub fn new(vcek_der: Vec<u8>) -> Self {
        Self { vcek_der }
    }

    pub fn verify_tinfoil_quote_with_vcek(
        request: &TinfoilQuoteVerificationRequest<'_>,
        vcek_der: &[u8],
    ) -> Result<VerifiedTinfoilQuote> {
        verify_tinfoil_quote_with_vcek(request, vcek_der)
    }
}

impl TinfoilQuoteVerifier for SevSnpTinfoilQuoteVerifier {
    fn verify_tinfoil_quote(
        &self,
        request: &TinfoilQuoteVerificationRequest<'_>,
    ) -> Result<VerifiedTinfoilQuote> {
        verify_tinfoil_quote_with_vcek(request, &self.vcek_der)
    }
}

/// Verify a raw AMD SNP report against a pre-resolved Genoa VCEK certificate.
pub fn verify_tinfoil_quote_with_vcek(
    request: &TinfoilQuoteVerificationRequest<'_>,
    vcek_der: &[u8],
) -> Result<VerifiedTinfoilQuote> {
    let now_epoch_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock is before the Unix epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| invalid("system time exceeds supported range"))?;
    verify_tinfoil_quote_with_vcek_at(request, vcek_der, now_epoch_ms)
}

/// Verify using an explicit Unix timestamp in milliseconds, for reproducible callers and tests.
pub fn verify_tinfoil_quote_with_vcek_at(
    request: &TinfoilQuoteVerificationRequest<'_>,
    vcek_der: &[u8],
    now_epoch_ms: u64,
) -> Result<VerifiedTinfoilQuote> {
    if request.attestation_format != TinfoilAttestationFormat::SevSnpGuestV2 {
        return Err(invalid(
            "SEV-SNP verifier received a non-SEV-SNP Tinfoil format",
        ));
    }
    let report = request.quote_bytes;
    if report.len() != REPORT_LEN {
        return Err(invalid(format!(
            "SEV-SNP report must be {REPORT_LEN} bytes"
        )));
    }
    let report_version = validate_report_version(report)?;
    if le_u32(report, 52)? != 1 {
        return Err(invalid("unsupported SEV-SNP report signature algorithm"));
    }
    verify_report_reserved_fields(report, report_version)?;
    let cert = x509_cert::Certificate::from_der(vcek_der)
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;
    verify_genoa_certificate_chain(&cert)?;
    let spki = cert.tbs_certificate().subject_public_key_info();
    let public_key = spki.subject_public_key.as_bytes().ok_or_else(|| {
        AttestationError::InvalidCertificate("VCEK public key is not octet-aligned".into())
    })?;
    let signature = report_signature(report)?;
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, public_key)
        .verify(&report[..SIGNED_LEN], &signature)
        .map_err(|_| invalid("SEV-SNP report signature is invalid"))?;

    verify_amd_vcek_extensions(&cert, &report[CHIP_ID], &report[REPORTED_TCB])?;
    verify_report_policy(report)?;

    let report_data_hex = hex(&report[REPORT_DATA]);
    let spki_sha256 = crate::certificate_spki_sha256_hex(request.live_tls_leaf_certificate_der)?;
    let expected_spki = spki_sha256.strip_prefix("sha256:").unwrap_or(&spki_sha256);
    if !report[REPORT_DATA.start..REPORT_DATA.start + 32]
        .iter()
        .zip(decode_hex_32(expected_spki)?.iter())
        .all(|(a, b)| a == b)
    {
        return Err(invalid(
            "SEV-SNP report_data does not bind the live TLS SPKI",
        ));
    }
    if !request
        .live_tls_spki_sha256
        .trim_start_matches("sha256:")
        .eq_ignore_ascii_case(expected_spki)
    {
        return Err(invalid(
            "live TLS SPKI digest does not match its certificate",
        ));
    }

    let (vcek_not_before_ms, expires_at_epoch_ms) =
        crate::certificate_validity_epoch_millis(vcek_der)?;
    ensure_vcek_validity(vcek_not_before_ms, expires_at_epoch_ms, now_epoch_ms)?;
    Ok(VerifiedTinfoilQuote::from_verified_quote(
        TinfoilAttestationFormat::SevSnpGuestV2,
        EvidenceHardware {
            cpu: CpuTeeKind::SevSnp,
            gpu: None,
        },
        format!("sev-snp:measurement:{}", hex(&report[MEASUREMENT])),
        report_data_hex,
        // Attestation time, like the TDX verifier: the VCEK's notBefore is
        // when AMD issued the chip key, not when this report was verified.
        format_utc_timestamp_millis(now_epoch_ms),
        format_utc_timestamp_millis(expires_at_epoch_ms),
        expires_at_epoch_ms,
    ))
}
fn ensure_vcek_validity(not_before_ms: u64, not_after_ms: u64, now_ms: u64) -> Result<()> {
    if now_ms < not_before_ms || now_ms >= not_after_ms {
        return Err(AttestationError::InvalidCertificate(
            "Genoa VCEK is outside its validity period".into(),
        ));
    }
    Ok(())
}

fn validate_report_version(report: &[u8]) -> Result<u32> {
    let version = le_u32(report, 0)?;
    if !(2..=5).contains(&version) {
        return Err(invalid(format!(
            "unsupported SEV-SNP report version {version}"
        )));
    }
    Ok(version)
}

fn verify_report_reserved_fields(report: &[u8], version: u32) -> Result<()> {
    let reserved_ranges = if version == 2 {
        [
            76..80,
            392..416,
            491..492,
            495..496,
            520..672,
            816..REPORT_LEN,
        ]
    } else {
        [
            76..80,
            395..416,
            491..492,
            495..496,
            520..672,
            816..REPORT_LEN,
        ]
    };
    for range in reserved_ranges {
        if report[range].iter().any(|byte| *byte != 0) {
            return Err(invalid("SEV-SNP report has non-zero reserved bytes"));
        }
    }
    if report[720..744].iter().any(|byte| *byte != 0)
        || report[792..816].iter().any(|byte| *byte != 0)
    {
        return Err(invalid("SEV-SNP P-384 signature has non-zero padding"));
    }
    let signer = le_u32(report, 72)?;
    if signer & !1 != 0 {
        return Err(invalid(
            "SEV-SNP report is not signed by a VCEK or has reserved signer bits",
        ));
    }
    Ok(())
}
fn verify_report_policy(report: &[u8]) -> Result<()> {
    let policy = u64::from_le_bytes(report[8..16].try_into().unwrap());
    if policy & (1 << 16) == 0
        || policy & (1 << 17) == 0
        || policy & (1 << 18) != 0
        || policy & (1 << 19) != 0
        || policy & (1 << 20) != 0
        || policy >> 26 != 0
    {
        return Err(invalid(
            "SEV-SNP guest policy does not meet Tinfoil requirements",
        ));
    }
    let platform = u64::from_le_bytes(report[64..72].try_into().unwrap());
    if platform & 1 == 0
        || platform & (1 << 1) == 0
        || platform & (3 << 6) != 0
        || platform >> 8 != 0
    {
        return Err(invalid(
            "SEV-SNP platform must have SMT and TSME enabled with reserved/TIO bits clear",
        ));
    }
    let reported_tcb = &report[REPORTED_TCB];
    let current_tcb = &report[56..64];
    let committed_tcb = &report[480..488];
    let launch_tcb = &report[496..504];
    for tcb in [reported_tcb, current_tcb, committed_tcb, launch_tcb] {
        if tcb[2..6].iter().any(|byte| *byte != 0) {
            return Err(invalid("SEV-SNP TCB has non-zero reserved SPL bytes"));
        }
    }
    if current_tcb != committed_tcb {
        return Err(invalid(
            "SEV-SNP report CURRENT_TCB differs from COMMITTED_TCB",
        ));
    }
    if !tcb_at_least(current_tcb, reported_tcb) {
        return Err(invalid("SEV-SNP CURRENT_TCB is below the reported TCB"));
    }
    for tcb in [reported_tcb, launch_tcb] {
        if tcb[0] < 7 || tcb[6] < 14 || tcb[7] < 72 {
            return Err(invalid(
                "SEV-SNP reported or launch TCB is below the Tinfoil minimum",
            ));
        }
    }
    if report[490] < 1 || (report[490] == 1 && report[489] < 55) || report[488] < 21 {
        return Err(invalid("SEV-SNP firmware version is below 1.55 build 21"));
    }
    if report[488..491] != report[492..495] {
        return Err(invalid(
            "SEV-SNP current firmware differs from committed firmware",
        ));
    }
    Ok(())
}

fn tcb_at_least(candidate: &[u8], minimum: &[u8]) -> bool {
    [0, 1, 6, 7]
        .into_iter()
        .all(|index| candidate[index] >= minimum[index])
}

fn verify_amd_vcek_extensions(
    cert: &x509_cert::Certificate,
    hwid: &[u8],
    tcb: &[u8],
) -> Result<()> {
    let extensions = cert.tbs_certificate().extensions().ok_or_else(|| {
        AttestationError::InvalidCertificate("VCEK has no AMD KDS extensions".into())
    })?;
    let mut found_hwid = false;
    let mut found_tcb = [false; 4];
    for ext in extensions {
        let oid = ext.extn_id.to_string();
        let value = ext.extn_value.as_bytes();
        match oid.as_str() {
            "1.3.6.1.4.1.3704.1.4" => {
                let decoded = if value.len() == 64 {
                    value
                } else if value.len() == 66 && value[..2] == [0x04, 0x40] {
                    &value[2..]
                } else {
                    return Err(AttestationError::InvalidCertificate(
                        "invalid AMD HWID extension".into(),
                    ));
                };
                if found_hwid || decoded != hwid {
                    return Err(invalid("VCEK AMD HWID extension does not match the report"));
                }
                found_hwid = true;
            }
            "1.3.6.1.4.1.3704.1.3.1" => {
                check_tcb_ext(value, tcb, &mut found_tcb[0], 0, "boot loader")?
            }
            "1.3.6.1.4.1.3704.1.3.2" => check_tcb_ext(value, tcb, &mut found_tcb[1], 1, "TEE")?,
            "1.3.6.1.4.1.3704.1.3.3" => check_tcb_ext(value, tcb, &mut found_tcb[2], 6, "SNP")?,
            "1.3.6.1.4.1.3704.1.3.8" => {
                check_tcb_ext(value, tcb, &mut found_tcb[3], 7, "microcode")?
            }
            _ => {}
        }
    }
    if !found_hwid || found_tcb.iter().any(|found| !found) {
        return Err(AttestationError::InvalidCertificate(
            "VCEK is missing required AMD HWID/TCB extensions".into(),
        ));
    }
    Ok(())
}

fn check_tcb_ext(
    value: &[u8],
    tcb: &[u8],
    found: &mut bool,
    index: usize,
    part: &str,
) -> Result<()> {
    let number = match value {
        [0x02, 0x01, value] => *value,
        [0x02, 0x02, 0, value] => *value,
        _ => {
            return Err(AttestationError::InvalidCertificate(format!(
                "invalid AMD {part} TCB extension"
            )))
        }
    };
    if *found || number != tcb[index] {
        return Err(invalid(format!(
            "VCEK AMD {part} TCB extension does not match the report"
        )));
    }
    *found = true;
    Ok(())
}

fn report_signature(report: &[u8]) -> Result<Vec<u8>> {
    let mut signature = Vec::with_capacity(96);
    for range in [672..744, 744..816] {
        let limb = &report[range];
        let mut raw = limb[..48].to_vec();
        raw.reverse();
        signature.extend(raw);
    }
    Ok(signature)
}

fn decode_hex_32(value: &str) -> Result<Vec<u8>> {
    if value.len() != 64 {
        return Err(invalid("TLS SPKI SHA-256 digest must be 32 bytes"));
    }
    (0..64)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| invalid("TLS SPKI digest is not hexadecimal"))
        })
        .collect()
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| invalid("truncated SEV-SNP report"))?
            .try_into()
            .unwrap(),
    ))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

fn verify_genoa_certificate_chain(vcek: &x509_cert::Certificate) -> Result<()> {
    let ask_der = base64::engine::general_purpose::STANDARD
        .decode(GENOA_ASK_DER_B64)
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;
    let ark_der = base64::engine::general_purpose::STANDARD
        .decode(GENOA_ARK_DER_B64)
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;
    let ask = x509_cert::Certificate::from_der(&ask_der)
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;
    let ark = x509_cert::Certificate::from_der(&ark_der)
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;
    verify_genoa_chain_certs(vcek, &ask, &ark, &ark_der)
}

fn verify_genoa_chain_certs(
    vcek: &x509_cert::Certificate,
    ask: &x509_cert::Certificate,
    ark: &x509_cert::Certificate,
    ark_der: &[u8],
) -> Result<()> {
    if crate::sha256_digest(ark_der) != format!("sha256:{GENOA_ARK_SHA256}")
        || ark.tbs_certificate().subject() != ark.tbs_certificate().issuer()
        || ask.tbs_certificate().issuer() != ark.tbs_certificate().subject()
        || vcek.tbs_certificate().issuer() != ask.tbs_certificate().subject()
    {
        return Err(AttestationError::InvalidCertificate(
            "VCEK does not chain to the pinned AMD Genoa ARK".into(),
        ));
    }
    verify_rsa_pss_certificate_signature(ark, ark)?;
    verify_rsa_pss_certificate_signature(ask, ark)?;
    verify_rsa_pss_certificate_signature(vcek, ask)
}

fn verify_rsa_pss_certificate_signature(
    certificate: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
) -> Result<()> {
    if certificate.signature_algorithm().oid.to_string() != "1.2.840.113549.1.1.10" {
        return Err(AttestationError::InvalidCertificate(
            "AMD certificate is not RSASSA-PSS".into(),
        ));
    }
    let key = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| {
            AttestationError::InvalidCertificate("AMD RSA key is not octet-aligned".into())
        })?;
    let (modulus, exponent) = parse_rsa_public_key(key)?;
    let tbs_der = certificate
        .tbs_certificate()
        .to_der()
        .map_err(|err| AttestationError::InvalidCertificate(err.to_string()))?;
    let signature = certificate.signature().as_bytes().ok_or_else(|| {
        AttestationError::InvalidCertificate(
            "AMD certificate signature is not octet-aligned".into(),
        )
    })?;
    RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    }
    .verify(&RSA_PSS_2048_8192_SHA384, &tbs_der, signature)
    .map_err(|_| {
        AttestationError::InvalidCertificate("AMD certificate signature is invalid".into())
    })
}

fn parse_rsa_public_key(der: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut pos = 0;
    let sequence = der_value(der, &mut pos, 0x30)?;
    if pos != der.len() {
        return Err(AttestationError::InvalidCertificate(
            "malformed RSA public key".into(),
        ));
    }
    let mut inner = 0;
    let mut modulus = der_value(sequence, &mut inner, 0x02)?;
    let exponent = der_value(sequence, &mut inner, 0x02)?;
    if inner != sequence.len() || modulus.is_empty() || exponent.is_empty() {
        return Err(AttestationError::InvalidCertificate(
            "malformed RSA public key".into(),
        ));
    }
    if modulus[0] == 0 {
        modulus = &modulus[1..];
    }
    Ok((modulus, exponent))
}

fn der_value<'a>(der: &'a [u8], pos: &mut usize, tag: u8) -> Result<&'a [u8]> {
    if der.get(*pos) != Some(&tag) {
        return Err(AttestationError::InvalidCertificate(
            "malformed DER certificate key".into(),
        ));
    }
    *pos += 1;
    let first = *der
        .get(*pos)
        .ok_or_else(|| AttestationError::InvalidCertificate("truncated DER length".into()))?;
    *pos += 1;
    let length = if first & 0x80 == 0 {
        first as usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || der.len().saturating_sub(*pos) < count {
            return Err(AttestationError::InvalidCertificate(
                "invalid DER length".into(),
            ));
        }
        let mut length = 0_usize;
        for byte in &der[*pos..*pos + count] {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(*byte as usize))
                .ok_or_else(|| {
                    AttestationError::InvalidCertificate("DER length overflow".into())
                })?;
        }
        *pos += count;
        length
    };
    let end = (*pos)
        .checked_add(length)
        .ok_or_else(|| AttestationError::InvalidCertificate("DER length overflow".into()))?;
    let value = der
        .get(*pos..end)
        .ok_or_else(|| AttestationError::InvalidCertificate("truncated DER value".into()))?;
    *pos = end;
    Ok(value)
}
fn invalid(message: impl Into<String>) -> AttestationError {
    AttestationError::InvalidEvidence(message.into())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn compliant_report() -> [u8; REPORT_LEN] {
        let mut report = [0; REPORT_LEN];
        report[..4].copy_from_slice(&2_u32.to_le_bytes());
        report[8..16].copy_from_slice(&((1_u64 << 16) | (1_u64 << 17)).to_le_bytes());
        report[64..72].copy_from_slice(&3_u64.to_le_bytes());
        let tcb = 7_u64 | (14_u64 << 48) | (72_u64 << 56);
        report[56..64].copy_from_slice(&tcb.to_le_bytes());
        report[384..392].copy_from_slice(&tcb.to_le_bytes());
        report[480..488].copy_from_slice(&tcb.to_le_bytes());
        report[496..504].copy_from_slice(&tcb.to_le_bytes());
        report[488] = 21;
        report[489] = 55;
        report[492..495].copy_from_slice(&[21, 55, 1]);
        report[490] = 1;
        report
    }

    #[test]
    fn accepts_minimum_supported_report_policy() {
        assert!(verify_report_policy(&compliant_report()).is_ok());
    }
    #[test]
    fn accepts_report_v3_cpuid_fields_and_rejects_unknown_versions() {
        let mut report = compliant_report();
        for version in 2_u32..=5 {
            report[..4].copy_from_slice(&version.to_le_bytes());
            if version >= 3 {
                report[392..395].copy_from_slice(&[0x19, 0x21, 0x02]);
            } else {
                report[392..395].fill(0);
            }
            assert_eq!(validate_report_version(&report).unwrap(), version);
            assert!(verify_report_reserved_fields(&report, version).is_ok());
        }
        report[..4].copy_from_slice(&3_u32.to_le_bytes());
        report[395] = 1;
        assert!(verify_report_reserved_fields(&report, 3).is_err());
        report[..4].copy_from_slice(&6_u32.to_le_bytes());
        assert!(validate_report_version(&report).is_err());
    }
    #[test]
    fn rejects_report_tcb_and_firmware_inconsistency() {
        let mut report = compliant_report();
        report[56] -= 1;
        assert!(verify_report_policy(&report).is_err());
        let mut report = compliant_report();
        report[492] -= 1;
        assert!(verify_report_policy(&report).is_err());
        let mut report = compliant_report();
        report[386] = 1;
        assert!(verify_report_policy(&report).is_err());
    }

    #[test]
    fn vcek_expiry_window_is_deterministic_and_exclusive_at_expiry() {
        assert!(ensure_vcek_validity(100, 200, 100).is_ok());
        assert!(ensure_vcek_validity(100, 200, 199).is_ok());
        assert!(ensure_vcek_validity(100, 200, 99).is_err());
        assert!(ensure_vcek_validity(100, 200, 200).is_err());
    }

    #[test]
    fn rejects_nonzero_reserved_report_bytes() {
        for offset in [76, 392, 491, 495, 520, 720, 816] {
            let mut report = compliant_report();
            report[offset] = 1;
            assert!(verify_report_reserved_fields(&report, 2).is_err());
        }
        let mut report = compliant_report();
        report[72] = 4;
        assert!(verify_report_reserved_fields(&report, 2).is_err());
    }

    fn genoa_chain() -> (x509_cert::Certificate, x509_cert::Certificate, Vec<u8>) {
        let ask_der = base64::engine::general_purpose::STANDARD
            .decode(GENOA_ASK_DER_B64)
            .unwrap();
        let ark_der = base64::engine::general_purpose::STANDARD
            .decode(GENOA_ARK_DER_B64)
            .unwrap();
        (
            x509_cert::Certificate::from_der(&ask_der).unwrap(),
            x509_cert::Certificate::from_der(&ark_der).unwrap(),
            ark_der,
        )
    }

    #[test]
    fn validates_pinned_genoa_ark_and_ask_signatures() {
        let (ask, ark, ark_der) = genoa_chain();
        assert!(verify_rsa_pss_certificate_signature(&ark, &ark).is_ok());
        assert!(verify_rsa_pss_certificate_signature(&ask, &ark).is_ok());
        assert_eq!(
            crate::sha256_digest(&ark_der),
            format!("sha256:{GENOA_ARK_SHA256}")
        );
    }

    #[test]
    fn rejects_wrong_ask_and_untrusted_ark() {
        let (ask, ark, ark_der) = genoa_chain();
        let mut wrong_ask_der = base64::engine::general_purpose::STANDARD
            .decode(GENOA_ASK_DER_B64)
            .unwrap();
        let last = wrong_ask_der.len() - 1;
        wrong_ask_der[last] ^= 1;
        let wrong_ask = x509_cert::Certificate::from_der(&wrong_ask_der).unwrap();
        assert!(verify_rsa_pss_certificate_signature(&wrong_ask, &ark).is_err());
        assert!(verify_genoa_chain_certs(&ask, &wrong_ask, &ark, &ark_der).is_err());
        let mut untrusted_ark = ark_der;
        untrusted_ark[0] ^= 1;
        assert!(verify_genoa_chain_certs(&ark, &ask, &ark, &untrusted_ark).is_err());
    }

    #[test]
    fn rejects_policy_and_platform_mutations() {
        for forbidden_bit in [18, 19, 20] {
            let mut report = compliant_report();
            report[8..16].copy_from_slice(
                &((1_u64 << 16) | (1_u64 << 17) | (1_u64 << forbidden_bit)).to_le_bytes(),
            );
            assert!(verify_report_policy(&report).is_err());
        }
        let mut report = compliant_report();
        report[8..16].copy_from_slice(&(1_u64 << 16).to_le_bytes());
        assert!(verify_report_policy(&report).is_err());
        for forbidden_platform_bit in [6, 7, 8] {
            let mut report = compliant_report();
            report[64..72]
                .copy_from_slice(&((3_u64 | (1_u64 << forbidden_platform_bit)).to_le_bytes()));
            assert!(verify_report_policy(&report).is_err());
        }
        let mut report = compliant_report();
        report[8..16].copy_from_slice(&0_u64.to_le_bytes());
        assert!(verify_report_policy(&report).is_err());
        let mut report = compliant_report();
        report[64..72].copy_from_slice(&1_u64.to_le_bytes());
        assert!(verify_report_policy(&report).is_err());
    }

    #[test]
    fn rejects_low_tcb_and_firmware_versions() {
        for (offset, value) in [(384, 6_u64), (496, 6_u64)] {
            let mut report = compliant_report();
            report[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(verify_report_policy(&report).is_err());
        }
        for offset in [488, 489, 490] {
            let mut report = compliant_report();
            report[offset] = 0;
            assert!(verify_report_policy(&report).is_err());
        }
    }

    // Real Tinfoil router evidence (report v3) with its live TLS leaf, and the
    // matching Genoa VCEK from AMD KDS, captured 2026-10-20. Test inputs only;
    // the pinned ARK/ASK chain remains the trust anchor.
    const LIVE_CAPTURE: &[u8] =
        include_bytes!("../../../fixtures/evidence/sev-snp/tinfoil-live-capture.json");
    const LIVE_VCEK: &[u8] = include_bytes!("../../../fixtures/evidence/sev-snp/tinfoil-vcek.der");
    const LIVE_CAPTURED_AT_MS: u64 = 1_792_500_345_231;

    fn verify_live(
        quote: &[u8],
        vcek: &[u8],
        spki: Option<&str>,
        now_ms: u64,
    ) -> Result<VerifiedTinfoilQuote> {
        let parsed = crate::parse_tinfoil_live_capture(LIVE_CAPTURE).unwrap();
        let request = TinfoilQuoteVerificationRequest {
            capture: &parsed.capture,
            attestation_format: parsed.attestation_format,
            quote_bytes: quote,
            live_tls_leaf_certificate_der: &parsed.live_tls_leaf_certificate_der,
            live_tls_spki_sha256: spki.unwrap_or(&parsed.capture.live_tls_spki_sha256),
        };
        verify_tinfoil_quote_with_vcek_at(&request, vcek, now_ms)
    }

    fn live_report() -> Vec<u8> {
        crate::parse_tinfoil_live_capture(LIVE_CAPTURE)
            .unwrap()
            .quote_bytes
    }

    #[test]
    fn real_tinfoil_evidence_verifies_with_attestation_time() {
        let verified = verify_live(&live_report(), LIVE_VCEK, None, LIVE_CAPTURED_AT_MS).unwrap();

        // issued_at is when the report was verified, never the VCEK's notBefore
        // (which made fresh verdicts expire before first use).
        assert_eq!(
            verified.issued_at,
            crate::format_utc_timestamp_millis(LIVE_CAPTURED_AT_MS)
        );
        let (_, vcek_not_after) = crate::certificate_validity_epoch_millis(LIVE_VCEK).unwrap();
        assert_eq!(verified.expires_at_epoch_ms, vcek_not_after);
        assert_eq!(verified.hardware.cpu, CpuTeeKind::SevSnp);
        assert!(verified.tee_measurement.starts_with("sev-snp:measurement:"));
    }

    #[test]
    fn real_tinfoil_evidence_mutations_fail_closed() {
        let report = live_report();
        let mutated_offsets = [
            ("policy", 8),
            ("report_data", REPORT_DATA.start),
            ("measurement", MEASUREMENT.start),
            ("reported_tcb", REPORTED_TCB.start),
            ("chip_id", CHIP_ID.start),
            ("signature_r", 0x2A0),
            ("signature_s", 0x2A0 + 72),
        ];
        for (field, offset) in mutated_offsets {
            let mut mutated = report.clone();
            mutated[offset] ^= 0x01;
            assert!(
                verify_live(&mutated, LIVE_VCEK, None, LIVE_CAPTURED_AT_MS).is_err(),
                "mutated {field} verified"
            );
        }

        let mut vcek = LIVE_VCEK.to_vec();
        let last = vcek.len() - 1;
        vcek[last] ^= 0x01;
        assert!(verify_live(&report, &vcek, None, LIVE_CAPTURED_AT_MS).is_err());

        let wrong_spki = format!("sha256:{}", "00".repeat(32));
        assert!(verify_live(&report, LIVE_VCEK, Some(&wrong_spki), LIVE_CAPTURED_AT_MS).is_err());
    }
}
