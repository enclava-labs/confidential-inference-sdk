use crate::{
    canonical_digest, parse_utc_timestamp_millis, verify_artifact_signature_with_keys,
    ArtifactDigest, ArtifactSignature, AttestationError, ChannelBindingKind, CpuTeeKind, Result,
    SignatureMetadata, TrustTier, TrustedSigningKey,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceValuesEnvelope {
    pub schema: String,
    pub payload: ReferenceValuesPayload,
    pub signature: ReferenceSignature,
}

impl ReferenceValuesEnvelope {
    pub const SCHEMA: &'static str = "confidential-inference.reference-values-envelope.v1";

    pub fn bundled_demo() -> Result<Self> {
        serde_json::from_str(include_str!(
            "../assets/reference-values/demo-envelope.json"
        ))
        .map_err(Into::into)
    }

    pub fn phase2_fixtures() -> Result<Self> {
        serde_json::from_str(include_str!(
            "../assets/reference-values/phase2-fixtures-envelope.json"
        ))
        .map_err(Into::into)
    }

    pub fn verify_signature(&self) -> Result<()> {
        self.verify_signature_with_keys(&crate::default_trusted_signing_keys())
    }

    pub fn verify_signature_with_keys(
        &self,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(crate::AttestationError::InvalidReferenceSignature);
        }
        self.payload.validate_for_activation()?;
        verify_artifact_signature_with_keys(&self.signature, &self.payload, trusted_signing_keys)
    }

    pub fn into_verified_payload(self) -> Result<ReferenceValuesPayload> {
        self.verify_signature()?;
        Ok(self.payload)
    }

    pub fn into_verified_payload_with_keys(
        self,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> Result<ReferenceValuesPayload> {
        self.verify_signature_with_keys(trusted_signing_keys)?;
        Ok(self.payload)
    }

    pub fn into_verified_update_from(
        self,
        current: &ReferenceValuesPayload,
    ) -> Result<ReferenceValuesPayload> {
        self.verify_signature()?;
        current.verify_update_to(&self.payload)?;
        Ok(self.payload)
    }

    pub fn into_verified_update_from_with_keys(
        self,
        current: &ReferenceValuesPayload,
        trusted_signing_keys: &[TrustedSigningKey],
    ) -> Result<ReferenceValuesPayload> {
        self.verify_signature_with_keys(trusted_signing_keys)?;
        current.verify_update_to(&self.payload)?;
        Ok(self.payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceValuesPayload {
    pub schema: String,
    pub version: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    pub valid_until_epoch_ms: u64,
    pub revocation_epoch: u64,
    pub minimum_acceptable_version: String,
    pub providers: BTreeMap<String, ProviderReference>,
}

impl ReferenceValuesPayload {
    pub const SCHEMA: &'static str = "confidential-inference.reference-values.v1";
    pub const SUPPORTED_SCHEMA_MAJOR: u32 = 1;

    pub fn digest(&self) -> Result<String> {
        self.validate_for_activation()?;
        canonical_digest(self)
    }

    fn validate_schema_major(&self) -> Result<()> {
        validate_reference_values_schema_major("schema", &self.schema)
    }

    pub fn validate_for_activation(&self) -> Result<()> {
        self.validate_schema_major()?;
        let valid_from = parse_reference_values_timestamp("valid_from", &self.valid_from)?;
        let valid_until = parse_reference_values_timestamp("valid_until", &self.valid_until)?;
        if valid_until != self.valid_until_epoch_ms {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "valid_until_epoch_ms {} does not match valid_until {}",
                self.valid_until_epoch_ms, self.valid_until
            )));
        }
        if valid_from >= valid_until {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "valid_from {} must be before valid_until {}",
                self.valid_from, self.valid_until
            )));
        }

        for (provider_id, provider) in &self.providers {
            for (route_id, route) in &provider.routes {
                route.validate_for_activation(provider_id, route_id)?;
            }
        }

        Ok(())
    }

    pub fn verify_update_to(&self, candidate: &ReferenceValuesPayload) -> Result<()> {
        self.validate_for_activation()?;
        if candidate.schema != Self::SCHEMA {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "unsupported reference values schema {}",
                candidate.schema
            )));
        }
        candidate.validate_for_activation()?;

        if candidate.issuer != self.issuer {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "candidate issuer {} does not match current issuer {}",
                candidate.issuer, self.issuer
            )));
        }

        if candidate.version.as_str() < self.version.as_str() {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "candidate reference values version {} is older than current {}",
                candidate.version, self.version
            )));
        }

        if candidate.version.as_str() < self.minimum_acceptable_version.as_str() {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "candidate reference values version {} is older than minimum acceptable {}",
                candidate.version, self.minimum_acceptable_version
            )));
        }

        if candidate.minimum_acceptable_version.as_str() < self.minimum_acceptable_version.as_str()
        {
            return Err(AttestationError::WeakeningReferenceValuesUpdate(format!(
                "minimum acceptable version moved backward from {} to {}",
                self.minimum_acceptable_version, candidate.minimum_acceptable_version
            )));
        }

        if candidate.revocation_epoch < self.revocation_epoch {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "candidate revocation epoch {} is older than current {}",
                candidate.revocation_epoch, self.revocation_epoch
            )));
        }

        for (provider_id, current_provider) in &self.providers {
            let Some(candidate_provider) = candidate.providers.get(provider_id) else {
                return Err(AttestationError::WeakeningReferenceValuesUpdate(format!(
                    "provider {provider_id} was removed"
                )));
            };

            fail_if_new_values(
                provider_id,
                "accepted_measurements",
                &current_provider.accepted_measurements,
                &candidate_provider.accepted_measurements,
            )?;

            for (route_id, current_route) in &current_provider.routes {
                let Some(candidate_route) = candidate_provider.routes.get(route_id) else {
                    return Err(AttestationError::WeakeningReferenceValuesUpdate(format!(
                        "route {route_id} was removed"
                    )));
                };

                current_route.verify_not_weakened_by(route_id, candidate_route)?;
            }
        }

        Ok(())
    }
}

fn parse_reference_values_timestamp(field: &str, value: &str) -> Result<u64> {
    parse_utc_timestamp_millis(value).map_err(|error| {
        AttestationError::InvalidReferenceValuesUpdate(format!(
            "{field} is not a valid reference-values timestamp: {error}"
        ))
    })
}

fn validate_reference_values_schema_major(field: &str, value: &str) -> Result<()> {
    let Some(version) = value
        .strip_prefix("confidential-inference.reference-values")
        .and_then(|rest| rest.strip_prefix(".v"))
    else {
        return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
            "{field} must start with confidential-inference.reference-values.v{}",
            ReferenceValuesPayload::SUPPORTED_SCHEMA_MAJOR
        )));
    };
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or_default();
    if major.is_empty() || major.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
            "{field} has malformed schema version {value}"
        )));
    }
    for part in parts {
        if part.is_empty() || part.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "{field} has malformed schema version {value}"
            )));
        }
    }
    let parsed_major = major.parse::<u32>().map_err(|_| {
        AttestationError::InvalidReferenceValuesUpdate(format!(
            "{field} has malformed schema version {value}"
        ))
    })?;
    if parsed_major != ReferenceValuesPayload::SUPPORTED_SCHEMA_MAJOR {
        return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
            "{field} major version {parsed_major} is not supported"
        )));
    }
    Ok(())
}

pub type ReferenceSignature = ArtifactSignature;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceValuesPin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_revocation_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_signing_identities: Vec<SignatureMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_millis: Option<u64>,
}

impl ReferenceValuesPin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn digest(digest: impl Into<String>) -> Self {
        Self::new().with_digest(digest)
    }

    pub fn version(version: impl Into<String>) -> Self {
        Self::new().with_version(version)
    }

    pub fn minimum_version(version: impl Into<String>) -> Self {
        Self::new().with_minimum_version(version)
    }

    pub fn minimum_revocation_epoch(epoch: u64) -> Self {
        Self::new().with_minimum_revocation_epoch(epoch)
    }

    pub fn digest_and_version(digest: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new().with_digest(digest).with_version(version)
    }

    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_minimum_version(mut self, version: impl Into<String>) -> Self {
        self.minimum_version = Some(version.into());
        self
    }

    pub fn with_minimum_revocation_epoch(mut self, epoch: u64) -> Self {
        self.minimum_revocation_epoch = Some(epoch);
        self
    }

    pub fn with_accepted_signing_identity(mut self, identity: SignatureMetadata) -> Self {
        self.accepted_signing_identities.push(identity);
        self
    }

    pub fn with_accepted_ed25519_signing_identity(
        self,
        signer: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        self.with_accepted_signing_identity(SignatureMetadata::ed25519(signer, key_id))
    }

    pub fn with_max_age_millis(mut self, millis: u64) -> Self {
        self.max_age_millis = Some(millis);
        self
    }

    pub fn verify(&self, reference_values: &ReferenceValuesPayload) -> Result<()> {
        let digest = reference_values.digest()?;
        self.verify_with_digest(reference_values, &digest)
    }

    pub fn verify_with_digest(
        &self,
        reference_values: &ReferenceValuesPayload,
        digest: &str,
    ) -> Result<()> {
        self.verify_with_digest_at(reference_values, digest, now_epoch_millis())
    }

    pub fn verify_with_digest_at(
        &self,
        reference_values: &ReferenceValuesPayload,
        digest: &str,
        now_epoch_millis: u64,
    ) -> Result<()> {
        if let Some(expected_digest) = &self.digest {
            if digest != expected_digest {
                return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                    "reference values digest pin mismatch: expected {expected_digest}, got {digest}"
                )));
            }
        }

        if let Some(expected_version) = &self.version {
            if &reference_values.version != expected_version {
                return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                    "reference values version pin mismatch: expected {expected_version}, got {}",
                    reference_values.version
                )));
            }
        }

        if let Some(minimum_version) = &self.minimum_version {
            if &reference_values.version < minimum_version {
                return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                    "reference values version {} is older than pinned minimum {minimum_version}",
                    reference_values.version
                )));
            }
        }

        if let Some(minimum_revocation_epoch) = self.minimum_revocation_epoch {
            if reference_values.revocation_epoch < minimum_revocation_epoch {
                return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                    "reference values revocation epoch {} is older than pinned minimum {minimum_revocation_epoch}",
                    reference_values.revocation_epoch
                )));
            }
        }

        if let Some(max_age_millis) = self.max_age_millis {
            let valid_from =
                parse_utc_timestamp_millis(&reference_values.valid_from).map_err(|error| {
                    AttestationError::InvalidReferenceValuesUpdate(format!(
                        "reference values valid_from is invalid: {error}"
                    ))
                })?;
            if valid_from > now_epoch_millis {
                return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                    "reference values valid_from {} is in the future",
                    reference_values.valid_from
                )));
            }
            let age_millis = now_epoch_millis.saturating_sub(valid_from);
            if age_millis > max_age_millis {
                return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                    "reference values age {age_millis}ms exceeds pinned maximum {max_age_millis}ms"
                )));
            }
        }

        Ok(())
    }

    pub fn verify_envelope_with_digest_at(
        &self,
        envelope: &ReferenceValuesEnvelope,
        digest: &str,
        now_epoch_millis: u64,
    ) -> Result<()> {
        if !self.accepted_signing_identities.is_empty()
            && !self.accepted_signing_identities.iter().any(|identity| {
                identity.signer == envelope.signature.signer
                    && identity.key_id == envelope.signature.key_id
                    && identity.alg == envelope.signature.alg
            })
        {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "reference values signing identity pin mismatch: got {}/{}/{}",
                envelope.signature.signer, envelope.signature.key_id, envelope.signature.alg
            )));
        }

        self.verify_with_digest_at(&envelope.payload, digest, now_epoch_millis)
    }
}

fn now_epoch_millis() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    millis.min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_json, DEMO_SIGNING_KEY_ID};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_compact::{KeyPair, Seed};

    const ROUTE_ID: &str = "demo:gpt-oss-120b:e2ee-gpt-oss-120b-p";
    const DEMO_REFERENCE_VALUES_DIGEST: &str =
        "sha256:23e42367da27793fd4600dcc48ad51c2c8b7b3124f541c23cfcc7c7c8ef474b9";
    const ACCEPTED_UPDATE_SIGNATURE: &str = "base64url:jbUNPHJ20IWay6uxwcSEGxAniDYILK_5F6CrauAQlW9hfRf8EVPOjhMrmenqYKxjtIaiqeMjqQMPYuFYYMtiDw";
    const ADDED_ARTIFACT_UPDATE_SIGNATURE: &str = "base64url:wiJCEW7bxp4ULjimRNuiS1JMTATePyBqELNqahVIhlfUQyd2vLiSNSCRSe0_CEayYZElWQpu2MFlbSz-XyokCg";
    const STALE_UPDATE_SIGNATURE: &str = "base64url:aAIG3yzmCdkT72HG1Vc4fOwS8JYBuqy1ZDMRXDMj1lKitLammFvn565RDwMV6wYgwWFk9Cs8ClgeNEDmYQ7FBA";
    const LOW_REVOCATION_UPDATE_SIGNATURE: &str = "base64url:y7ISOxL2iPy9PaBB_if4IKOFOepbN1TCce9mmyDNxNcg1AQIF8g-u16-KQsFfgjDVs43lRU9ye05y8-pQULYAw";
    const BROADENED_MEASUREMENT_UPDATE_SIGNATURE: &str = "base64url:02d7UEswYAGWa80Gfo2n9VXHBeF8lWTXb8PWPhT4RWll5PqumtLE-RgWGrb0-IT7jEvEmd0IhU-IVmughPAbAA";
    const KEY_CHANGED_UPDATE_SIGNATURE: &str = "base64url:SJnwpC8B2EvKTvjnlK-5MDZ-qmyq8-ONfpWRLoBj99cRxP-3vUZaDu61XqsYgRfIHZtPZ8qtAcxY_tYaMGycDA";
    const ARTIFACT_REMOVED_UPDATE_SIGNATURE: &str = "base64url:MryCW2GmnJ3MMPmEkgddLP0oAq8bEhCbFDLfpiLS19SvYOPCuAHuSXEqGDpUtpcSDXuKUrhy5gKk6iu2b-_nBQ";
    const CPU_BROADENED_UPDATE_SIGNATURE: &str = "base64url:VBo6WB58OcZJ-ujRC2N_tg71suY8DYtSC86bnl__lS2cicuxQ2NB5a2QLrbPxDfnk6GOntIz4iplp4KrlcqnCg";
    const ROUTE_REMOVED_UPDATE_SIGNATURE: &str = "base64url:2XbULFUSZQd7C8jsNyBb5sRWAz3OJQuVbVUDwUrYLub1U10UOYQciQR-nGEVbEqSma52yBhcW1TrXRppVJsoDQ";
    const PROVIDER_REMOVED_UPDATE_SIGNATURE: &str = "base64url:CpkNOGgohVkxLgV0SMeKPCYiil9oz-i52lHBXxDV6t_1Av1XLJC253zl_fxCmJx1wTm2irrtsP3tXMqXJr47BA";
    const MIN_VERSION_ROLLBACK_SIGNATURE: &str = "base64url:xdAkt4PAfzdEQ6WXefgYGC5EWCOiUovRE9kG5d4RcWQ_LBp1VHyDjOyGMbWAoAuyJeS7MBGZNenk6h66bZhyBg";

    #[test]
    fn bundled_reference_values_signature_verifies() {
        let envelope = ReferenceValuesEnvelope::bundled_demo().unwrap();
        envelope.verify_signature().unwrap();
        assert_eq!(
            envelope.payload.digest().unwrap(),
            DEMO_REFERENCE_VALUES_DIGEST
        );
    }

    #[test]
    fn tampered_reference_values_signature_fails() {
        let mut envelope = ReferenceValuesEnvelope::bundled_demo().unwrap();
        envelope.payload.version = "tampered".into();

        assert!(envelope.verify_signature().is_err());
    }

    #[test]
    fn signed_non_weakening_reference_values_update_is_accepted() {
        let current = demo_payload();
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        candidate.revocation_epoch = 2;
        let update = signed_update(candidate, ACCEPTED_UPDATE_SIGNATURE);

        let accepted = update.into_verified_update_from(&current).unwrap();

        assert_eq!(accepted.version, "2026-07-06-demo");
        assert_eq!(accepted.revocation_epoch, 2);
    }

    #[test]
    fn signed_stricter_reference_values_update_is_accepted() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .model_artifacts
            .push(ArtifactDigest {
                kind: "sbom".into(),
                name: "runtime.spdx.json".into(),
                digest: "sha256:demo-sbom".into(),
            });
        let update = signed_update(candidate, ADDED_ARTIFACT_UPDATE_SIGNATURE);

        let accepted = update.into_verified_update_from(&current).unwrap();

        assert_eq!(
            accepted
                .providers
                .get("demo")
                .unwrap()
                .routes
                .get(ROUTE_ID)
                .unwrap()
                .model_artifacts
                .len(),
            3
        );
    }

    #[test]
    fn signed_stale_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = current.clone();
        candidate.version = "2026-07-04-demo".into();
        candidate.revocation_epoch = 2;
        let update = signed_update(candidate, STALE_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::InvalidReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn signed_lower_revocation_epoch_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate.revocation_epoch = 0;
        let update = signed_update(candidate, LOW_REVOCATION_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::InvalidReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn signed_minimum_version_rollback_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate.minimum_acceptable_version = "2026-07-04-demo".into();
        let update = signed_update(candidate, MIN_VERSION_ROLLBACK_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn signed_broadened_measurement_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .accepted_measurements
            .push("sha256:unexpected-measurement".into());
        let update = signed_update(candidate, BROADENED_MEASUREMENT_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn signed_broadened_cpu_tee_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .accepted_cpu_tees
            .push(CpuTeeKind::SevSnp);
        let update = signed_update(candidate, CPU_BROADENED_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn signed_route_key_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .e2ee_public_key_digest = "sha256:weaker-key".into();
        let update = signed_update(candidate, KEY_CHANGED_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn route_response_signing_key_reference_values_update_fails_closed() {
        let mut current = demo_payload();
        current
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .response_signing_key_digest = Some("sha256:demo-response-signing-key".into());

        let mut removed_candidate = next_version(&current);
        removed_candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .response_signing_key_digest = None;
        assert!(matches!(
            current.verify_update_to(&removed_candidate),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));

        let mut changed_candidate = next_version(&current);
        changed_candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .response_signing_key_digest = Some("sha256:other-response-signing-key".into());
        assert!(matches!(
            current.verify_update_to(&changed_candidate),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn signed_artifact_removal_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .model_artifacts
            .truncate(1);
        let update = signed_update(candidate, ARTIFACT_REMOVED_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn signed_route_removal_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate.providers.get_mut("demo").unwrap().routes.clear();
        let update = signed_update(candidate, ROUTE_REMOVED_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn signed_provider_removal_reference_values_update_fails_closed() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate.providers.clear();
        let update = signed_update(candidate, PROVIDER_REMOVED_UPDATE_SIGNATURE);

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::WeakeningReferenceValuesUpdate(_))
        ));
    }

    #[test]
    fn unsigned_reference_values_update_fails_before_update_evaluation() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate.providers.clear();
        let mut update = signed_update(candidate, ACCEPTED_UPDATE_SIGNATURE);
        update.signature.value =
            "base64url:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .into();

        assert!(matches!(
            update.into_verified_update_from(&current),
            Err(AttestationError::InvalidArtifactSignature(_))
        ));
    }

    #[test]
    fn reference_values_digest_accepts_same_major_schema_metadata() {
        let mut payload = demo_payload();
        payload.schema = "confidential-inference.reference-values.v1.1".into();

        assert!(payload.digest().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn reference_values_digest_rejects_unknown_major_schema_metadata() {
        let mut payload = demo_payload();
        payload.schema = "confidential-inference.reference-values.v2".into();

        let error = payload.digest().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidReferenceValuesUpdate(message)
                if message.contains("schema major version 2 is not supported")
        ));
    }

    #[test]
    fn reference_values_envelope_rejects_unknown_major_payload_schema_before_activation() {
        let mut envelope = ReferenceValuesEnvelope::bundled_demo().unwrap();
        envelope.payload.schema = "confidential-inference.reference-values.v2".into();

        let error = envelope.into_verified_payload().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidReferenceValuesUpdate(message)
                if message.contains("schema major version 2 is not supported")
        ));
    }

    #[test]
    fn reference_values_payload_rejects_valid_until_epoch_mismatch() {
        let mut payload = demo_payload();
        payload.valid_until_epoch_ms += 1;

        let error = payload.validate_for_activation().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidReferenceValuesUpdate(message)
                if message.contains("valid_until_epoch_ms")
        ));
    }

    #[test]
    fn reference_values_payload_rejects_empty_validity_window() {
        let mut payload = demo_payload();
        payload.valid_from = payload.valid_until.clone();

        let error = payload.validate_for_activation().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidReferenceValuesUpdate(message)
                if message.contains("must be before valid_until")
        ));
    }

    #[test]
    fn reference_values_payload_rejects_route_valid_until_epoch_mismatch() {
        let mut payload = demo_payload();
        payload
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .valid_until_epoch_ms += 1;

        let error = payload.validate_for_activation().unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidReferenceValuesUpdate(message)
                if message.contains("route demo/")
                    && message.contains("valid_until_epoch_ms")
        ));
    }

    #[test]
    fn reference_values_update_rejects_candidate_route_valid_until_epoch_mismatch() {
        let current = demo_payload();
        let mut candidate = next_version(&current);
        candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .valid_until_epoch_ms += 1;

        let error = current.verify_update_to(&candidate).unwrap_err();

        assert!(matches!(
            error,
            AttestationError::InvalidReferenceValuesUpdate(message)
                if message.contains("route demo/")
                    && message.contains("valid_until_epoch_ms")
        ));
    }

    #[test]
    fn reference_values_reject_noncanonical_workload_image_manifest() {
        let mut payload = demo_payload();
        payload
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .workload_images = vec![
            manifest_image("worker", 'b'),
            manifest_image("gateway", 'a'),
        ];

        let error = payload.validate_for_activation().unwrap_err();

        assert!(error.to_string().contains("not sorted and unique"));
    }

    #[test]
    fn reference_values_reject_unpinned_workload_image() {
        let mut payload = demo_payload();
        let route = payload
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap();
        route.workload_images = vec![crate::WorkloadImage {
            service: "worker".into(),
            reference: "example/worker:latest".into(),
            digest: String::new(),
        }];

        let error = payload.validate_for_activation().unwrap_err();

        assert!(error.to_string().contains("unpinned workload image"));
    }

    #[test]
    fn reference_values_update_cannot_remove_or_change_workload_manifest() {
        let mut current = demo_payload();
        current
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .workload_images = vec![manifest_image("worker", 'a')];
        let mut candidate = next_version(&current);
        candidate
            .providers
            .get_mut("demo")
            .unwrap()
            .routes
            .get_mut(ROUTE_ID)
            .unwrap()
            .workload_images
            .clear();

        let error = current.verify_update_to(&candidate).unwrap_err();

        assert!(matches!(
            error,
            AttestationError::WeakeningReferenceValuesUpdate(message)
                if message.contains("workload_images")
        ));
    }

    #[test]
    fn reference_values_pin_accepts_matching_digest_version_and_signing_identity() {
        let envelope = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let digest = envelope.payload.digest().unwrap();
        let now = crate::parse_utc_timestamp_millis("2026-07-05T00:00:01Z").unwrap();
        let pin = ReferenceValuesPin::digest_and_version(
            digest.clone(),
            envelope.payload.version.clone(),
        )
        .with_minimum_version("2026-07-05-demo")
        .with_minimum_revocation_epoch(1)
        .with_accepted_ed25519_signing_identity("confidential-inference", DEMO_SIGNING_KEY_ID)
        .with_max_age_millis(2_000);

        pin.verify_envelope_with_digest_at(&envelope, &digest, now)
            .unwrap();
    }

    #[test]
    fn reference_values_pin_rejects_digest_mismatch() {
        let payload = demo_payload();
        let digest = payload.digest().unwrap();

        let error = ReferenceValuesPin::digest("sha256:wrong")
            .verify_with_digest(&payload, &digest)
            .unwrap_err();

        assert!(error.to_string().contains("digest pin mismatch"));
    }

    #[test]
    fn reference_values_pin_rejects_signing_identity_mismatch() {
        let envelope = ReferenceValuesEnvelope::bundled_demo().unwrap();
        let digest = envelope.payload.digest().unwrap();
        let now = crate::parse_utc_timestamp_millis("2026-07-05T00:00:01Z").unwrap();
        let pin = ReferenceValuesPin::new()
            .with_accepted_ed25519_signing_identity("confidential-inference", "other-key");

        let error = pin
            .verify_envelope_with_digest_at(&envelope, &digest, now)
            .unwrap_err();

        assert!(error.to_string().contains("signing identity pin mismatch"));
    }

    #[test]
    fn reference_values_pin_rejects_max_age_exceeded() {
        let payload = demo_payload();
        let digest = payload.digest().unwrap();
        let now = crate::parse_utc_timestamp_millis("2026-07-05T00:00:01Z").unwrap();

        let error = ReferenceValuesPin::new()
            .with_max_age_millis(500)
            .verify_with_digest_at(&payload, &digest, now)
            .unwrap_err();

        assert!(error.to_string().contains("exceeds pinned maximum"));
    }

    #[test]
    fn reference_values_pin_rejects_revocation_epoch_below_pinned_minimum() {
        let payload = demo_payload();
        let digest = payload.digest().unwrap();

        let error = ReferenceValuesPin::minimum_revocation_epoch(payload.revocation_epoch + 1)
            .verify_with_digest(&payload, &digest)
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("revocation epoch 1 is older than pinned minimum 2"));
    }

    fn demo_payload() -> ReferenceValuesPayload {
        ReferenceValuesEnvelope::bundled_demo()
            .unwrap()
            .into_verified_payload()
            .unwrap()
    }

    fn manifest_image(service: &str, digest_byte: char) -> crate::WorkloadImage {
        let digest_hex = digest_byte.to_string().repeat(64);
        let digest = format!("sha256:{digest_hex}");
        crate::WorkloadImage {
            service: service.into(),
            reference: format!("example/{service}@{digest}"),
            digest,
        }
    }

    fn next_version(current: &ReferenceValuesPayload) -> ReferenceValuesPayload {
        let mut candidate = current.clone();
        candidate.version = "2026-07-06-demo".into();
        candidate.revocation_epoch = 2;
        candidate
    }

    fn signed_update(
        payload: ReferenceValuesPayload,
        _legacy_signature: &str,
    ) -> ReferenceValuesEnvelope {
        let canonical = canonical_json(&payload).unwrap();
        let key_pair = KeyPair::from_seed(Seed::new([71_u8; 32]));
        let signature = format!(
            "base64url:{}",
            URL_SAFE_NO_PAD.encode(key_pair.sk.sign(canonical.as_bytes(), None).as_ref())
        );
        ReferenceValuesEnvelope {
            schema: ReferenceValuesEnvelope::SCHEMA.into(),
            payload,
            signature: ArtifactSignature {
                signer: "confidential-inference".into(),
                key_id: DEMO_SIGNING_KEY_ID.into(),
                alg: "ed25519".into(),
                value: signature,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReference {
    pub accepted_measurements: Vec<String>,
    pub routes: BTreeMap<String, RouteReference>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteReference {
    pub canonical_model: String,
    pub provider_model: String,
    pub evidence_family: String,
    pub channel_binding_kind: ChannelBindingKind,
    pub trust_tier: TrustTier,
    pub accepted_cpu_tees: Vec<CpuTeeKind>,
    pub e2ee_public_key_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_signing_key_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_spki_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workload_images: Vec<crate::WorkloadImage>,
    pub workload_image_digest: String,
    pub model_artifacts: Vec<ArtifactDigest>,
    pub valid_until: String,
    pub valid_until_epoch_ms: u64,
}

impl RouteReference {
    fn validate_for_activation(&self, provider_id: &str, route_id: &str) -> Result<()> {
        let valid_until = parse_reference_values_timestamp(
            &format!("route {provider_id}/{route_id} valid_until"),
            &self.valid_until,
        )?;
        if valid_until != self.valid_until_epoch_ms {
            return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                "route {provider_id}/{route_id} valid_until_epoch_ms {} does not match valid_until {}",
                self.valid_until_epoch_ms, self.valid_until
            )));
        }
        if !self.workload_images.is_empty() {
            if self
                .workload_images
                .iter()
                .any(|image| !image.is_digest_pinned())
            {
                return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                    "route {provider_id}/{route_id} contains an unpinned workload image"
                )));
            }
            let mut canonical = self.workload_images.clone();
            canonical.sort();
            canonical.dedup();
            if canonical != self.workload_images {
                return Err(AttestationError::InvalidReferenceValuesUpdate(format!(
                    "route {provider_id}/{route_id} workload_images are not sorted and unique"
                )));
            }
        }
        Ok(())
    }

    fn verify_not_weakened_by(&self, route_id: &str, candidate: &RouteReference) -> Result<()> {
        fail_if_changed(
            route_id,
            "canonical_model",
            &self.canonical_model,
            &candidate.canonical_model,
        )?;
        fail_if_changed(
            route_id,
            "provider_model",
            &self.provider_model,
            &candidate.provider_model,
        )?;
        fail_if_changed(
            route_id,
            "evidence_family",
            &self.evidence_family,
            &candidate.evidence_family,
        )?;
        fail_if_changed(
            route_id,
            "channel_binding_kind",
            &self.channel_binding_kind,
            &candidate.channel_binding_kind,
        )?;
        fail_if_changed(
            route_id,
            "trust_tier",
            &self.trust_tier,
            &candidate.trust_tier,
        )?;
        fail_if_changed(
            route_id,
            "e2ee_public_key_digest",
            &self.e2ee_public_key_digest,
            &candidate.e2ee_public_key_digest,
        )?;
        match (
            &self.response_signing_key_digest,
            &candidate.response_signing_key_digest,
        ) {
            (Some(current), Some(candidate)) => {
                fail_if_changed(route_id, "response_signing_key_digest", current, candidate)?;
            }
            (Some(current), None) => {
                return Err(AttestationError::WeakeningReferenceValuesUpdate(format!(
                    "{route_id} removed required response_signing_key_digest value {current:?}"
                )));
            }
            (None, _) => {}
        }
        match (&self.tls_spki_sha256, &candidate.tls_spki_sha256) {
            (Some(current), Some(candidate)) => {
                fail_if_changed(route_id, "tls_spki_sha256", current, candidate)?;
            }
            (Some(current), None) => {
                return Err(AttestationError::WeakeningReferenceValuesUpdate(format!(
                    "{route_id} removed required tls_spki_sha256 value {current:?}"
                )));
            }
            (None, _) => {}
        }
        if !self.workload_images.is_empty() {
            fail_if_changed(
                route_id,
                "workload_images",
                &self.workload_images,
                &candidate.workload_images,
            )?;
        }
        fail_if_changed(
            route_id,
            "workload_image_digest",
            &self.workload_image_digest,
            &candidate.workload_image_digest,
        )?;

        fail_if_new_values(
            route_id,
            "accepted_cpu_tees",
            &self.accepted_cpu_tees,
            &candidate.accepted_cpu_tees,
        )?;

        fail_if_missing_values(
            route_id,
            "model_artifacts",
            &self.model_artifacts,
            &candidate.model_artifacts,
        )
    }
}

fn fail_if_changed<T>(scope: &str, field: &str, current: &T, candidate: &T) -> Result<()>
where
    T: PartialEq + std::fmt::Debug,
{
    if current == candidate {
        Ok(())
    } else {
        Err(AttestationError::WeakeningReferenceValuesUpdate(format!(
            "{scope} changed {field} from {current:?} to {candidate:?}"
        )))
    }
}

fn fail_if_new_values<T>(scope: &str, field: &str, current: &[T], candidate: &[T]) -> Result<()>
where
    T: PartialEq + std::fmt::Debug,
{
    if let Some(new_value) = candidate.iter().find(|candidate_value| {
        !current
            .iter()
            .any(|current_value| current_value == *candidate_value)
    }) {
        return Err(AttestationError::WeakeningReferenceValuesUpdate(format!(
            "{scope} added unreviewed {field} value {new_value:?}"
        )));
    }

    Ok(())
}

fn fail_if_missing_values<T>(scope: &str, field: &str, current: &[T], candidate: &[T]) -> Result<()>
where
    T: PartialEq + std::fmt::Debug,
{
    if let Some(missing_value) = current.iter().find(|current_value| {
        !candidate
            .iter()
            .any(|candidate_value| candidate_value == *current_value)
    }) {
        return Err(AttestationError::WeakeningReferenceValuesUpdate(format!(
            "{scope} removed required {field} value {missing_value:?}"
        )));
    }

    Ok(())
}
