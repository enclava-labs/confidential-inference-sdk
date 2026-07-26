use crate::{
    canonical_digest, canonical_json, certificate_spki_sha256_hex,
    certificate_validity_epoch_millis, format_utc_timestamp_millis, sha256_digest,
    verify_artifact_signature_with_keys, ArtifactDigest, ArtifactSignature, AttestationError,
    CpuTeeKind, Result, TrustedSigningKey, WorkloadImage,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};

const ACI_NONCE_BYTES: usize = 32;
const MAX_ACI_QUOTE_BYTES: usize = 1024 * 1024;
const MAX_ACI_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_ACI_KEYS: usize = 32;
const MAX_ACI_WORKLOAD_IMAGES: usize = 256;
const MAX_ACI_MODEL_ARTIFACTS: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AciKeyAlgorithm {
    Ed25519,
    X25519,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AciKeyUsage {
    RequestEncryption,
    ResponseSigning,
    ControlPlaneSigning,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AciWorkloadKey {
    pub key_id: String,
    pub alg: AciKeyAlgorithm,
    pub public_key_base64url: String,
    pub usages: Vec<AciKeyUsage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AciCapabilities {
    pub request_encryption: bool,
    pub response_signing: bool,
    pub streaming: bool,
    pub model_binding: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AciSourceProvenance {
    pub source_repository: String,
    pub source_commit_sha256: String,
    pub dependency_sbom_sha256: String,
    pub workload_images: Vec<WorkloadImage>,
    pub model_artifacts: Vec<ArtifactDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AciWorkloadKeyset {
    pub schema: String,
    pub workload_id: String,
    pub deployment_id: String,
    pub canonical_model: String,
    pub epoch: u64,
    pub tee_kind: CpuTeeKind,
    pub issued_at: String,
    pub issued_at_epoch_ms: u64,
    pub not_before: String,
    pub not_before_epoch_ms: u64,
    pub stale_after: String,
    pub stale_after_epoch_ms: u64,
    pub not_after: String,
    pub not_after_epoch_ms: u64,
    pub tls_spki_sha256: String,
    pub capabilities: AciCapabilities,
    pub provenance: AciSourceProvenance,
    pub keys: Vec<AciWorkloadKey>,
}

impl AciWorkloadKeyset {
    pub const SCHEMA: &'static str = "confidential-inference.aci-workload-keyset.v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AciWorkloadKeysetEnvelope {
    pub schema: String,
    pub payload: AciWorkloadKeyset,
    pub signature: ArtifactSignature,
}

impl AciWorkloadKeysetEnvelope {
    pub const SCHEMA: &'static str = "confidential-inference.aci-workload-keyset-envelope.v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AciEvidence {
    pub schema: String,
    pub keyset: AciWorkloadKeysetEnvelope,
    pub nonce: String,
    pub attestation_format: String,
    pub quote_base64: String,
    pub live_tls_spki_sha256: String,
    pub live_tls_leaf_certificate_der_base64: String,
}

impl AciEvidence {
    pub const SCHEMA: &'static str = "confidential-inference.aci-evidence.v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AciKeysetCheckpoint {
    pub workload_id: String,
    pub epoch: u64,
    pub keyset_digest: String,
}

#[derive(Debug)]
pub struct AciVerificationRequest<'a> {
    pub evidence: &'a AciEvidence,
    pub expected_nonce: &'a str,
    pub expected_workload_id: &'a str,
    pub minimum_epoch: u64,
    pub checkpoint: Option<&'a AciKeysetCheckpoint>,
    pub now_epoch_ms: u64,
    pub maximum_keyset_age_ms: u64,
    pub trusted_identity_keys: &'a [TrustedSigningKey],
}

#[derive(Debug)]
pub struct AciQuoteVerificationRequest<'a> {
    pub workload_id: &'a str,
    pub tee_kind: &'a CpuTeeKind,
    pub attestation_format: &'a str,
    pub quote_bytes: &'a [u8],
    pub expected_report_data: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedAciQuote {
    pub attestation_format: String,
    pub tee_kind: CpuTeeKind,
    pub tee_measurement: String,
    pub report_data: String,
    pub issued_at: String,
    pub issued_at_epoch_ms: u64,
    pub expires_at: String,
    pub expires_at_epoch_ms: u64,
    pub collateral_valid_until_epoch_ms: u64,
}

pub trait AciQuoteVerifier: Send + Sync {
    fn verify_aci_quote(
        &self,
        request: &AciQuoteVerificationRequest<'_>,
    ) -> Result<VerifiedAciQuote>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FailClosedAciQuoteVerifier;

impl AciQuoteVerifier for FailClosedAciQuoteVerifier {
    fn verify_aci_quote(
        &self,
        request: &AciQuoteVerificationRequest<'_>,
    ) -> Result<VerifiedAciQuote> {
        Err(aci_error(format!(
            "ACI {} evidence requires a configured quote verifier",
            request.attestation_format
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedAciWorkloadKeyset {
    pub keyset: AciWorkloadKeyset,
    pub keyset_digest: String,
    pub identity_signer: String,
    pub identity_key_id: String,
    pub tee_measurement: String,
    pub tls_spki_sha256: String,
    pub verified_at_epoch_ms: u64,
    pub cache_expires_at: String,
    pub cache_expires_at_epoch_ms: u64,
    pub cache_ttl_ms: u64,
}

impl VerifiedAciWorkloadKeyset {
    pub fn checkpoint(&self) -> AciKeysetCheckpoint {
        AciKeysetCheckpoint {
            workload_id: self.keyset.workload_id.clone(),
            epoch: self.keyset.epoch,
            keyset_digest: self.keyset_digest.clone(),
        }
    }
}

pub fn aci_expected_report_data(nonce: &str, keyset: &AciWorkloadKeyset) -> Result<String> {
    let nonce_bytes = decode_aci_nonce(nonce)?;
    let keyset_json = canonical_json(keyset)?;

    let mut nonce_binding = b"confidential-inference.aci.nonce.v1\0".to_vec();
    nonce_binding.extend_from_slice(&nonce_bytes);
    let mut keyset_binding = b"confidential-inference.aci.keyset.v1\0".to_vec();
    keyset_binding.extend_from_slice(keyset_json.as_bytes());

    Ok(format!(
        "{}{}",
        sha256_digest(&nonce_binding).trim_start_matches("sha256:"),
        sha256_digest(&keyset_binding).trim_start_matches("sha256:")
    ))
}

pub fn verify_aci_workload_keyset(
    request: AciVerificationRequest<'_>,
    quote_verifier: &dyn AciQuoteVerifier,
) -> Result<VerifiedAciWorkloadKeyset> {
    let evidence = request.evidence;
    if evidence.schema != AciEvidence::SCHEMA {
        return Err(aci_error(format!(
            "unsupported ACI evidence schema {}",
            evidence.schema
        )));
    }
    if evidence.keyset.schema != AciWorkloadKeysetEnvelope::SCHEMA {
        return Err(aci_error(format!(
            "unsupported ACI keyset envelope schema {}",
            evidence.keyset.schema
        )));
    }
    validate_keyset(&evidence.keyset.payload)?;
    verify_artifact_signature_with_keys(
        &evidence.keyset.signature,
        &evidence.keyset.payload,
        request.trusted_identity_keys,
    )
    .map_err(|error| aci_error(format!("identity endorsement failed: {error}")))?;

    let keyset = &evidence.keyset.payload;
    if keyset.workload_id != request.expected_workload_id {
        return Err(aci_error(format!(
            "workload {} does not match expected workload {}",
            keyset.workload_id, request.expected_workload_id
        )));
    }
    if keyset.epoch < request.minimum_epoch {
        return Err(aci_error(format!(
            "keyset epoch {} is below minimum epoch {}",
            keyset.epoch, request.minimum_epoch
        )));
    }
    if request.maximum_keyset_age_ms == 0 {
        return Err(aci_error("maximum_keyset_age_ms must be non-zero"));
    }
    validate_keyset_time(keyset, request.now_epoch_ms, request.maximum_keyset_age_ms)?;

    let keyset_digest = canonical_digest(keyset)?;
    validate_checkpoint(request.checkpoint, keyset, &keyset_digest)?;

    if evidence.nonce != request.expected_nonce {
        return Err(aci_error("ACI nonce does not match the expected challenge"));
    }
    decode_aci_nonce(&evidence.nonce)?;
    if evidence.attestation_format.trim().is_empty() || evidence.attestation_format.len() > 256 {
        return Err(aci_error("ACI attestation format is empty or too long"));
    }

    let certificate_der = decode_bounded_base64(
        "live TLS leaf certificate",
        &evidence.live_tls_leaf_certificate_der_base64,
        MAX_ACI_CERTIFICATE_BYTES,
    )?;
    let computed_tls_spki = format!(
        "sha256:{}",
        certificate_spki_sha256_hex(&certificate_der)
            .map_err(|error| aci_error(format!("live TLS certificate is invalid: {error}")))?
    );
    if evidence.live_tls_spki_sha256 != computed_tls_spki
        || keyset.tls_spki_sha256 != computed_tls_spki
    {
        return Err(aci_error(
            "live TLS SPKI does not match the identity-endorsed keyset",
        ));
    }
    let (certificate_not_before, certificate_not_after) =
        certificate_validity_epoch_millis(&certificate_der)
            .map_err(|error| aci_error(format!("live TLS certificate is invalid: {error}")))?;
    if request.now_epoch_ms < certificate_not_before
        || request.now_epoch_ms >= certificate_not_after
    {
        return Err(aci_error(
            "live TLS certificate is outside its validity window",
        ));
    }

    let expected_report_data = aci_expected_report_data(&evidence.nonce, keyset)?;
    let quote_bytes =
        decode_bounded_base64("ACI quote", &evidence.quote_base64, MAX_ACI_QUOTE_BYTES)?;
    if quote_bytes.is_empty() {
        return Err(aci_error("ACI quote is empty"));
    }
    let verified_quote = quote_verifier.verify_aci_quote(&AciQuoteVerificationRequest {
        workload_id: &keyset.workload_id,
        tee_kind: &keyset.tee_kind,
        attestation_format: &evidence.attestation_format,
        quote_bytes: &quote_bytes,
        expected_report_data: &expected_report_data,
    })?;
    validate_verified_quote(
        &verified_quote,
        keyset,
        &evidence.attestation_format,
        &expected_report_data,
        request.now_epoch_ms,
    )?;

    let cache_expires_at_epoch_ms = [
        keyset.stale_after_epoch_ms,
        keyset.not_after_epoch_ms,
        verified_quote.expires_at_epoch_ms,
        verified_quote.collateral_valid_until_epoch_ms,
        certificate_not_after,
    ]
    .into_iter()
    .min()
    .ok_or_else(|| aci_error("ACI cache validity bounds are empty"))?;
    if cache_expires_at_epoch_ms <= request.now_epoch_ms {
        return Err(aci_error(
            "ACI verification result has no positive cache lifetime",
        ));
    }

    Ok(VerifiedAciWorkloadKeyset {
        keyset: keyset.clone(),
        keyset_digest,
        identity_signer: evidence.keyset.signature.signer.clone(),
        identity_key_id: evidence.keyset.signature.key_id.clone(),
        tee_measurement: verified_quote.tee_measurement,
        tls_spki_sha256: computed_tls_spki,
        verified_at_epoch_ms: request.now_epoch_ms,
        cache_expires_at: format_utc_timestamp_millis(cache_expires_at_epoch_ms),
        cache_expires_at_epoch_ms,
        cache_ttl_ms: cache_expires_at_epoch_ms.saturating_sub(request.now_epoch_ms),
    })
}

fn validate_keyset(keyset: &AciWorkloadKeyset) -> Result<()> {
    if keyset.schema != AciWorkloadKeyset::SCHEMA {
        return Err(aci_error(format!(
            "unsupported ACI workload keyset schema {}",
            keyset.schema
        )));
    }
    for (field, value) in [
        ("workload_id", keyset.workload_id.as_str()),
        ("deployment_id", keyset.deployment_id.as_str()),
        ("canonical_model", keyset.canonical_model.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 256 {
            return Err(aci_error(format!(
                "ACI keyset {field} is empty or too long"
            )));
        }
    }
    validate_sha256("tls_spki_sha256", &keyset.tls_spki_sha256)?;
    validate_provenance(&keyset.provenance, keyset.capabilities.model_binding)?;
    validate_keys(&keyset.keys, &keyset.capabilities)
}

fn validate_keyset_time(keyset: &AciWorkloadKeyset, now: u64, maximum_age: u64) -> Result<()> {
    for (field, timestamp, epoch) in [
        (
            "issued_at",
            keyset.issued_at.as_str(),
            keyset.issued_at_epoch_ms,
        ),
        (
            "not_before",
            keyset.not_before.as_str(),
            keyset.not_before_epoch_ms,
        ),
        (
            "stale_after",
            keyset.stale_after.as_str(),
            keyset.stale_after_epoch_ms,
        ),
        (
            "not_after",
            keyset.not_after.as_str(),
            keyset.not_after_epoch_ms,
        ),
    ] {
        if format_utc_timestamp_millis(epoch) != timestamp {
            return Err(aci_error(format!(
                "ACI keyset {field} timestamp does not match its epoch"
            )));
        }
    }
    if !(keyset.issued_at_epoch_ms <= keyset.not_before_epoch_ms
        && keyset.not_before_epoch_ms < keyset.stale_after_epoch_ms
        && keyset.stale_after_epoch_ms <= keyset.not_after_epoch_ms)
    {
        return Err(aci_error("ACI keyset validity bounds are inconsistent"));
    }
    if now < keyset.issued_at_epoch_ms || now < keyset.not_before_epoch_ms {
        return Err(aci_error("ACI keyset is not yet valid"));
    }
    if now >= keyset.stale_after_epoch_ms || now >= keyset.not_after_epoch_ms {
        return Err(aci_error("ACI keyset is stale or expired"));
    }
    if now.saturating_sub(keyset.issued_at_epoch_ms) > maximum_age {
        return Err(aci_error("ACI keyset exceeds the configured maximum age"));
    }
    Ok(())
}

fn validate_provenance(provenance: &AciSourceProvenance, model_binding: bool) -> Result<()> {
    if provenance.source_repository.trim().is_empty() || provenance.source_repository.len() > 2048 {
        return Err(aci_error("ACI source repository is empty or too long"));
    }
    validate_sha256("source_commit_sha256", &provenance.source_commit_sha256)?;
    validate_sha256("dependency_sbom_sha256", &provenance.dependency_sbom_sha256)?;
    if provenance.workload_images.is_empty()
        || provenance.workload_images.len() > MAX_ACI_WORKLOAD_IMAGES
        || provenance
            .workload_images
            .iter()
            .any(|image| !image.is_digest_pinned())
    {
        return Err(aci_error(
            "ACI provenance requires a bounded, digest-pinned workload image manifest",
        ));
    }
    let mut images = provenance.workload_images.clone();
    images.sort();
    images.dedup();
    if images != provenance.workload_images {
        return Err(aci_error(
            "ACI workload image manifest must be sorted and unique",
        ));
    }
    if provenance.model_artifacts.len() > MAX_ACI_MODEL_ARTIFACTS
        || (model_binding && provenance.model_artifacts.is_empty())
    {
        return Err(aci_error(
            "ACI model-binding capability requires bounded model artifacts",
        ));
    }
    for artifact in &provenance.model_artifacts {
        if artifact.kind.trim().is_empty() || artifact.name.trim().is_empty() {
            return Err(aci_error("ACI model artifact metadata is incomplete"));
        }
        validate_sha256("model artifact digest", &artifact.digest)?;
    }
    if provenance.model_artifacts.windows(2).any(|pair| {
        (&pair[0].kind, &pair[0].name, &pair[0].digest)
            >= (&pair[1].kind, &pair[1].name, &pair[1].digest)
    }) {
        return Err(aci_error("ACI model artifacts must be sorted and unique"));
    }
    Ok(())
}

fn validate_keys(keys: &[AciWorkloadKey], capabilities: &AciCapabilities) -> Result<()> {
    if keys.is_empty() || keys.len() > MAX_ACI_KEYS {
        return Err(aci_error(
            "ACI keyset has an invalid number of workload keys",
        ));
    }
    if keys.windows(2).any(|pair| pair[0].key_id >= pair[1].key_id) {
        return Err(aci_error("ACI workload key IDs must be sorted and unique"));
    }
    for key in keys {
        if key.key_id.is_empty()
            || key.key_id.len() > 128
            || !key
                .key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(aci_error("ACI workload key ID is invalid"));
        }
        let public_key = URL_SAFE_NO_PAD
            .decode(&key.public_key_base64url)
            .map_err(|error| aci_error(format!("ACI workload key is not base64url: {error}")))?;
        if public_key.len() != 32 || URL_SAFE_NO_PAD.encode(&public_key) != key.public_key_base64url
        {
            return Err(aci_error(
                "ACI Ed25519/X25519 workload keys must be canonical 32-byte values",
            ));
        }
        if key.usages.is_empty() {
            return Err(aci_error("ACI workload key has no declared usage"));
        }
        let mut usages = key.usages.clone();
        usages.sort();
        usages.dedup();
        if usages != key.usages {
            return Err(aci_error(
                "ACI workload key usages must be sorted and unique",
            ));
        }
        if key.usages.iter().any(|usage| match usage {
            AciKeyUsage::RequestEncryption => key.alg != AciKeyAlgorithm::X25519,
            AciKeyUsage::ResponseSigning | AciKeyUsage::ControlPlaneSigning => {
                key.alg != AciKeyAlgorithm::Ed25519
            }
        }) {
            return Err(aci_error(
                "ACI workload key algorithm is incompatible with its declared usage",
            ));
        }
    }
    let has_request_key = keys.iter().any(|key| {
        key.alg == AciKeyAlgorithm::X25519 && key.usages.contains(&AciKeyUsage::RequestEncryption)
    });
    let has_response_key = keys.iter().any(|key| {
        key.alg == AciKeyAlgorithm::Ed25519 && key.usages.contains(&AciKeyUsage::ResponseSigning)
    });
    if capabilities.request_encryption && !has_request_key {
        return Err(aci_error(
            "ACI request-encryption capability has no X25519 workload key",
        ));
    }
    if capabilities.response_signing && !has_response_key {
        return Err(aci_error(
            "ACI response-signing capability has no Ed25519 workload key",
        ));
    }
    Ok(())
}

fn validate_checkpoint(
    checkpoint: Option<&AciKeysetCheckpoint>,
    keyset: &AciWorkloadKeyset,
    keyset_digest: &str,
) -> Result<()> {
    let Some(checkpoint) = checkpoint else {
        return Ok(());
    };
    validate_sha256("checkpoint keyset_digest", &checkpoint.keyset_digest)?;
    if checkpoint.workload_id != keyset.workload_id {
        return Err(aci_error("ACI checkpoint belongs to a different workload"));
    }
    if keyset.epoch < checkpoint.epoch {
        return Err(aci_error(format!(
            "ACI keyset epoch {} rolls back checkpoint epoch {}",
            keyset.epoch, checkpoint.epoch
        )));
    }
    if keyset.epoch == checkpoint.epoch && keyset_digest != checkpoint.keyset_digest {
        return Err(aci_error(
            "ACI keyset changed without advancing its monotonic epoch",
        ));
    }
    Ok(())
}

fn validate_verified_quote(
    quote: &VerifiedAciQuote,
    keyset: &AciWorkloadKeyset,
    attestation_format: &str,
    expected_report_data: &str,
    now: u64,
) -> Result<()> {
    if quote.attestation_format != attestation_format {
        return Err(aci_error("ACI quote verifier returned a different format"));
    }
    if quote.tee_kind != keyset.tee_kind {
        return Err(aci_error(
            "ACI quote verifier returned a different TEE kind",
        ));
    }
    if quote.report_data != expected_report_data {
        return Err(aci_error(
            "ACI quote report_data does not bind the nonce and complete keyset",
        ));
    }
    if quote.tee_measurement.trim().is_empty() {
        return Err(aci_error("ACI quote has no verified TEE measurement"));
    }
    if format_utc_timestamp_millis(quote.issued_at_epoch_ms) != quote.issued_at
        || format_utc_timestamp_millis(quote.expires_at_epoch_ms) != quote.expires_at
    {
        return Err(aci_error("ACI verified quote timestamps are inconsistent"));
    }
    if now < quote.issued_at_epoch_ms || now >= quote.expires_at_epoch_ms {
        return Err(aci_error(
            "ACI verified quote is outside its validity window",
        ));
    }
    if quote.collateral_valid_until_epoch_ms <= now {
        return Err(aci_error("ACI quote collateral is expired"));
    }
    Ok(())
}

fn decode_aci_nonce(nonce: &str) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|error| aci_error(format!("ACI nonce is not base64url: {error}")))?;
    if decoded.len() != ACI_NONCE_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != nonce {
        return Err(aci_error(
            "ACI nonce must be a canonical 32-byte base64url value",
        ));
    }
    Ok(decoded)
}

fn decode_bounded_base64(field: &str, value: &str, maximum: usize) -> Result<Vec<u8>> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|error| aci_error(format!("{field} is not base64: {error}")))?;
    if decoded.len() > maximum || STANDARD.encode(&decoded) != value {
        return Err(aci_error(format!(
            "{field} is not canonical or exceeds {maximum} bytes"
        )));
    }
    Ok(decoded)
}

fn validate_sha256(field: &str, value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(aci_error(format!(
            "{field} is not a canonical sha256 digest"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(aci_error(format!(
            "{field} is not a canonical sha256 digest"
        )));
    }
    Ok(())
}

fn aci_error(message: impl Into<String>) -> AttestationError {
    AttestationError::InvalidAciEvidence(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_json, parse_utc_timestamp_millis};
    use ed25519_compact::{KeyPair, Seed};
    use serde_json::json;

    const WORKLOAD_ID: &str = "aci-workload/gpt-oss-120b";
    const ATTESTATION_FORMAT: &str = "test/tdx-quote-v1";

    #[derive(Clone)]
    struct StaticAciQuoteVerifier {
        quote: VerifiedAciQuote,
    }

    impl AciQuoteVerifier for StaticAciQuoteVerifier {
        fn verify_aci_quote(
            &self,
            request: &AciQuoteVerificationRequest<'_>,
        ) -> Result<VerifiedAciQuote> {
            assert_eq!(request.workload_id, WORKLOAD_ID);
            assert_eq!(request.tee_kind, &CpuTeeKind::Tdx);
            assert_eq!(request.attestation_format, ATTESTATION_FORMAT);
            assert_eq!(request.quote_bytes, &[9_u8; 48]);
            assert_eq!(request.expected_report_data.len(), 128);
            Ok(self.quote.clone())
        }
    }

    #[test]
    fn verifies_identity_endorsed_quote_bound_keyset_and_uses_tightest_cache_bound() {
        let (evidence, verifier, trusted_key) = fixture();

        let verified = verify_fixture(&evidence, &verifier, &trusted_key, None).unwrap();

        assert_eq!(verified.keyset.workload_id, WORKLOAD_ID);
        assert_eq!(verified.keyset.epoch, 7);
        assert_eq!(verified.identity_signer, "aci-test-identity");
        assert_eq!(verified.identity_key_id, "identity-2026");
        assert_eq!(verified.tls_spki_sha256, fixture_tls_spki());
        assert_eq!(
            verified.cache_expires_at_epoch_ms,
            timestamp("2026-07-05T12:20:00Z")
        );
        assert_eq!(verified.cache_ttl_ms, 20 * 60 * 1_000);
        assert_eq!(verified.checkpoint().keyset_digest, verified.keyset_digest);
    }

    #[test]
    fn rejects_payload_tampering_without_identity_resignature() {
        let (mut evidence, verifier, trusted_key) = fixture();
        evidence.keyset.payload.capabilities.streaming = true;

        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("identity endorsement failed"));
    }

    #[test]
    fn quote_binds_all_capabilities_even_after_valid_identity_rotation() {
        let (mut evidence, verifier, trusted_key) = fixture();
        evidence.keyset.payload.capabilities.streaming = true;
        evidence.keyset = sign_keyset(evidence.keyset.payload.clone());

        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("complete keyset"));
    }

    #[test]
    fn quote_binds_complete_source_and_image_provenance() {
        let (mut evidence, verifier, trusted_key) = fixture();
        evidence.keyset.payload.provenance.source_commit_sha256 =
            format!("sha256:{}", "e".repeat(64));
        evidence.keyset = sign_keyset(evidence.keyset.payload.clone());

        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("complete keyset"));
    }

    #[test]
    fn rejects_wrong_or_noncanonical_nonce() {
        let (mut evidence, verifier, trusted_key) = fixture();
        let wrong_nonce = URL_SAFE_NO_PAD.encode([8_u8; 32]);
        let error = verify_with_nonce(&evidence, &verifier, &trusted_key, &wrong_nonce, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("expected challenge"));

        evidence.nonce = "padded==".into();
        let error = verify_with_nonce(&evidence, &verifier, &trusted_key, "padded==", None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("nonce is not base64url"));
    }

    #[test]
    fn fresh_nonce_must_be_bound_by_the_verified_quote() {
        let (mut evidence, verifier, trusted_key) = fixture();
        evidence.nonce = URL_SAFE_NO_PAD.encode([8_u8; 32]);

        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("nonce and complete keyset"));
    }

    #[test]
    fn rejects_live_tls_identity_not_endorsed_by_keyset() {
        let (mut evidence, verifier, trusted_key) = fixture();
        evidence.live_tls_spki_sha256 = format!("sha256:{}", "0".repeat(64));

        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("live TLS SPKI"));
    }

    #[test]
    fn rejects_epoch_rollback_and_same_epoch_equivocation() {
        let (mut evidence, verifier, trusted_key) = fixture();
        let error = verify_aci_workload_keyset(
            AciVerificationRequest {
                evidence: &evidence,
                expected_nonce: &evidence.nonce,
                expected_workload_id: WORKLOAD_ID,
                minimum_epoch: 8,
                checkpoint: None,
                now_epoch_ms: now(),
                maximum_keyset_age_ms: 2 * 60 * 60 * 1_000,
                trusted_identity_keys: std::slice::from_ref(&trusted_key),
            },
            &verifier,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("below minimum epoch"));

        let verified = verify_fixture(&evidence, &verifier, &trusted_key, None).unwrap();
        let checkpoint = verified.checkpoint();
        evidence.keyset.payload.deployment_id = "deployment-b".into();
        evidence.keyset = sign_keyset(evidence.keyset.payload.clone());
        let rebound_verifier = verifier_for(&evidence);
        let error = verify_fixture(
            &evidence,
            &rebound_verifier,
            &trusted_key,
            Some(&checkpoint),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("without advancing its monotonic epoch"));

        let (mut rotated, _, trusted_key) = fixture();
        rotated.keyset.payload.epoch = checkpoint.epoch + 1;
        rotated.keyset.payload.keys[0].public_key_base64url = URL_SAFE_NO_PAD.encode([33_u8; 32]);
        rotated.keyset = sign_keyset(rotated.keyset.payload.clone());
        let rotated_verifier = verifier_for(&rotated);

        let verified =
            verify_fixture(&rotated, &rotated_verifier, &trusted_key, Some(&checkpoint)).unwrap();

        assert_eq!(verified.keyset.epoch, checkpoint.epoch + 1);
        assert_ne!(verified.keyset_digest, checkpoint.keyset_digest);
    }

    #[test]
    fn rejects_duplicate_key_ids_and_wrong_key_sizes() {
        let (mut evidence, verifier, trusted_key) = fixture();
        evidence.keyset.payload.keys[1].key_id = evidence.keyset.payload.keys[0].key_id.clone();
        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("sorted and unique"));

        let (mut evidence, verifier, trusted_key) = fixture();
        evidence.keyset.payload.keys[0].public_key_base64url = URL_SAFE_NO_PAD.encode([1_u8; 31]);
        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical 32-byte"));
    }

    #[test]
    fn rejects_unsupported_key_algorithms_during_strict_deserialization() {
        let (evidence, _, _) = fixture();
        let mut value = serde_json::to_value(evidence).unwrap();
        value["keyset"]["payload"]["keys"][0]["alg"] = json!("rsa");

        let error = serde_json::from_value::<AciEvidence>(value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown variant `rsa`"));
    }

    #[test]
    fn rejects_stale_keyset_expired_collateral_and_missing_quote_backend() {
        let (mut evidence, verifier, trusted_key) = fixture();
        evidence.keyset.payload.stale_after = "2026-07-05T11:59:59Z".into();
        evidence.keyset.payload.stale_after_epoch_ms = timestamp("2026-07-05T11:59:59Z");
        evidence.keyset = sign_keyset(evidence.keyset.payload.clone());
        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("stale or expired"));

        let (evidence, mut verifier, trusted_key) = fixture();
        verifier.quote.collateral_valid_until_epoch_ms = now();
        let error = verify_fixture(&evidence, &verifier, &trusted_key, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("collateral is expired"));

        let (evidence, _, trusted_key) = fixture();
        let error = verify_fixture(&evidence, &FailClosedAciQuoteVerifier, &trusted_key, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires a configured quote verifier"));
    }

    fn fixture() -> (AciEvidence, StaticAciQuoteVerifier, TrustedSigningKey) {
        let keyset = fixture_keyset();
        let envelope = sign_keyset(keyset);
        let nonce = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let evidence = AciEvidence {
            schema: AciEvidence::SCHEMA.into(),
            keyset: envelope,
            nonce,
            attestation_format: ATTESTATION_FORMAT.into(),
            quote_base64: STANDARD.encode([9_u8; 48]),
            live_tls_spki_sha256: fixture_tls_spki(),
            live_tls_leaf_certificate_der_base64: crate::tls::TEST_CERT_DER_BASE64.into(),
        };
        let verifier = verifier_for(&evidence);
        (evidence, verifier, trusted_identity_key())
    }

    fn fixture_keyset() -> AciWorkloadKeyset {
        AciWorkloadKeyset {
            schema: AciWorkloadKeyset::SCHEMA.into(),
            workload_id: WORKLOAD_ID.into(),
            deployment_id: "deployment-a".into(),
            canonical_model: "gpt-oss-120b".into(),
            epoch: 7,
            tee_kind: CpuTeeKind::Tdx,
            issued_at: "2026-07-05T11:00:00Z".into(),
            issued_at_epoch_ms: timestamp("2026-07-05T11:00:00Z"),
            not_before: "2026-07-05T11:05:45Z".into(),
            not_before_epoch_ms: timestamp("2026-07-05T11:05:45Z"),
            stale_after: "2026-07-05T13:00:00Z".into(),
            stale_after_epoch_ms: timestamp("2026-07-05T13:00:00Z"),
            not_after: "2026-07-06T10:00:00Z".into(),
            not_after_epoch_ms: timestamp("2026-07-06T10:00:00Z"),
            tls_spki_sha256: fixture_tls_spki(),
            capabilities: AciCapabilities {
                request_encryption: true,
                response_signing: true,
                streaming: false,
                model_binding: true,
            },
            provenance: AciSourceProvenance {
                source_repository: "https://example.invalid/aci-workload".into(),
                source_commit_sha256: format!("sha256:{}", "c".repeat(64)),
                dependency_sbom_sha256: format!("sha256:{}", "d".repeat(64)),
                workload_images: vec![WorkloadImage {
                    service: "inference".into(),
                    reference: format!("example/inference@sha256:{}", "a".repeat(64)),
                    digest: format!("sha256:{}", "a".repeat(64)),
                }],
                model_artifacts: vec![ArtifactDigest {
                    kind: "weights".into(),
                    name: "gpt-oss-120b".into(),
                    digest: format!("sha256:{}", "b".repeat(64)),
                }],
            },
            keys: vec![
                AciWorkloadKey {
                    key_id: "enc-1".into(),
                    alg: AciKeyAlgorithm::X25519,
                    public_key_base64url: URL_SAFE_NO_PAD.encode([11_u8; 32]),
                    usages: vec![AciKeyUsage::RequestEncryption],
                },
                AciWorkloadKey {
                    key_id: "sig-1".into(),
                    alg: AciKeyAlgorithm::Ed25519,
                    public_key_base64url: URL_SAFE_NO_PAD.encode([22_u8; 32]),
                    usages: vec![AciKeyUsage::ResponseSigning],
                },
            ],
        }
    }

    fn sign_keyset(payload: AciWorkloadKeyset) -> AciWorkloadKeysetEnvelope {
        let key_pair = identity_key_pair();
        let payload_json = canonical_json(&payload).unwrap();
        let signature = key_pair.sk.sign(payload_json.as_bytes(), None);
        AciWorkloadKeysetEnvelope {
            schema: AciWorkloadKeysetEnvelope::SCHEMA.into(),
            payload,
            signature: ArtifactSignature {
                signer: "aci-test-identity".into(),
                key_id: "identity-2026".into(),
                alg: "ed25519".into(),
                value: format!("base64url:{}", URL_SAFE_NO_PAD.encode(signature.as_ref())),
            },
        }
    }

    fn trusted_identity_key() -> TrustedSigningKey {
        TrustedSigningKey::new(
            "aci-test-identity",
            "identity-2026",
            URL_SAFE_NO_PAD.encode(identity_key_pair().pk.as_ref()),
        )
    }

    fn identity_key_pair() -> KeyPair {
        KeyPair::from_seed(Seed::new([53_u8; 32]))
    }

    fn verifier_for(evidence: &AciEvidence) -> StaticAciQuoteVerifier {
        StaticAciQuoteVerifier {
            quote: VerifiedAciQuote {
                attestation_format: ATTESTATION_FORMAT.into(),
                tee_kind: CpuTeeKind::Tdx,
                tee_measurement: format!("sha256:{}", "f".repeat(64)),
                report_data: aci_expected_report_data(&evidence.nonce, &evidence.keyset.payload)
                    .unwrap(),
                issued_at: "2026-07-05T11:59:00Z".into(),
                issued_at_epoch_ms: timestamp("2026-07-05T11:59:00Z"),
                expires_at: "2026-07-05T12:30:00Z".into(),
                expires_at_epoch_ms: timestamp("2026-07-05T12:30:00Z"),
                collateral_valid_until_epoch_ms: timestamp("2026-07-05T12:20:00Z"),
            },
        }
    }

    fn verify_fixture(
        evidence: &AciEvidence,
        verifier: &dyn AciQuoteVerifier,
        trusted_key: &TrustedSigningKey,
        checkpoint: Option<&AciKeysetCheckpoint>,
    ) -> Result<VerifiedAciWorkloadKeyset> {
        verify_with_nonce(evidence, verifier, trusted_key, &evidence.nonce, checkpoint)
    }

    fn verify_with_nonce(
        evidence: &AciEvidence,
        verifier: &dyn AciQuoteVerifier,
        trusted_key: &TrustedSigningKey,
        expected_nonce: &str,
        checkpoint: Option<&AciKeysetCheckpoint>,
    ) -> Result<VerifiedAciWorkloadKeyset> {
        verify_aci_workload_keyset(
            AciVerificationRequest {
                evidence,
                expected_nonce,
                expected_workload_id: WORKLOAD_ID,
                minimum_epoch: 7,
                checkpoint,
                now_epoch_ms: now(),
                maximum_keyset_age_ms: 2 * 60 * 60 * 1_000,
                trusted_identity_keys: std::slice::from_ref(trusted_key),
            },
            verifier,
        )
    }

    fn fixture_tls_spki() -> String {
        format!("sha256:{}", crate::tls::TEST_SPKI_SHA256)
    }

    fn now() -> u64 {
        timestamp("2026-07-05T12:00:00Z")
    }

    fn timestamp(value: &str) -> u64 {
        parse_utc_timestamp_millis(value).unwrap()
    }
}
