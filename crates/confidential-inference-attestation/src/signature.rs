use crate::{canonical_json, AttestationError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_compact::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

pub const DEMO_SIGNING_KEY_ID: &str = "confidential-inference-demo-ed25519-2026";
pub const DEMO_SIGNING_PUBLIC_KEY_BASE64URL: &str = "4oqJcHUzMr1y_vQT5rCy7xtKrdp6osFB8jNxKmh2s1E";
pub const PHASE2_FIXTURE_SIGNING_KEY_ID: &str =
    "confidential-inference-phase2-fixture-ed25519-2026";
pub const PHASE2_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL: &str =
    "cN-eInmtvsbRK_KSEYTJIi6yTthSAFv2QBOfUuWc2a4";
pub const COMPATIBILITY_FIXTURE_SIGNING_KEY_ID: &str =
    "confidential-inference-compatibility-fixture-ed25519-2026";
pub const COMPATIBILITY_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL: &str =
    "bjLBl0Hwr4JgYSrpn9E9ijiURyLgiWTdI5c49VKmFTs";
pub const ALIAS_MATRIX_FIXTURE_SIGNING_KEY_ID: &str =
    "confidential-inference-alias-matrix-fixture-ed25519-2026";
pub const ALIAS_MATRIX_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL: &str =
    "zxs36F3ACu6U8QEIs38VHio3s64qDK53Uh-DSI25xNc";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSignature {
    pub signer: String,
    pub key_id: String,
    pub alg: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedSigningKey {
    pub signer: String,
    pub key_id: String,
    pub public_key_base64url: String,
}

impl TrustedSigningKey {
    pub fn new(
        signer: impl Into<String>,
        key_id: impl Into<String>,
        public_key_base64url: impl Into<String>,
    ) -> Self {
        Self {
            signer: signer.into(),
            key_id: key_id.into(),
            public_key_base64url: public_key_base64url.into(),
        }
    }

    pub fn demo() -> Self {
        Self {
            signer: "confidential-inference".into(),
            key_id: DEMO_SIGNING_KEY_ID.into(),
            public_key_base64url: DEMO_SIGNING_PUBLIC_KEY_BASE64URL.into(),
        }
    }

    pub fn phase2_fixture() -> Self {
        Self {
            signer: "confidential-inference".into(),
            key_id: PHASE2_FIXTURE_SIGNING_KEY_ID.into(),
            public_key_base64url: PHASE2_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL.into(),
        }
    }

    pub fn compatibility_fixture() -> Self {
        Self {
            signer: "confidential-inference".into(),
            key_id: COMPATIBILITY_FIXTURE_SIGNING_KEY_ID.into(),
            public_key_base64url: COMPATIBILITY_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL.into(),
        }
    }

    pub fn alias_matrix_fixture() -> Self {
        Self {
            signer: "confidential-inference".into(),
            key_id: ALIAS_MATRIX_FIXTURE_SIGNING_KEY_ID.into(),
            public_key_base64url: ALIAS_MATRIX_FIXTURE_SIGNING_PUBLIC_KEY_BASE64URL.into(),
        }
    }
}

pub fn verify_artifact_signature<T: Serialize>(
    signature: &ArtifactSignature,
    payload: &T,
) -> Result<()> {
    verify_artifact_signature_with_keys(signature, payload, &default_trusted_signing_keys())
}

pub fn default_trusted_signing_keys() -> Vec<TrustedSigningKey> {
    vec![
        TrustedSigningKey::demo(),
        TrustedSigningKey::phase2_fixture(),
        TrustedSigningKey::compatibility_fixture(),
        TrustedSigningKey::alias_matrix_fixture(),
    ]
}

pub fn verify_artifact_signature_with_keys<T: Serialize>(
    signature: &ArtifactSignature,
    payload: &T,
    trusted_signing_keys: &[TrustedSigningKey],
) -> Result<()> {
    if signature.signer.is_empty() || signature.key_id.is_empty() || signature.value.is_empty() {
        return Err(AttestationError::InvalidArtifactSignature(
            "signature metadata is incomplete".into(),
        ));
    }

    if signature.alg != "ed25519" {
        return Err(AttestationError::UnsupportedSignatureAlgorithm(
            signature.alg.clone(),
        ));
    }

    let signing_key = trusted_signing_key(signature, trusted_signing_keys).ok_or_else(|| {
        AttestationError::UnknownArtifactSigningKey {
            signer: signature.signer.clone(),
            key_id: signature.key_id.clone(),
        }
    })?;

    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(&signing_key.public_key_base64url)
        .map_err(|err| {
            AttestationError::InvalidArtifactSignature(format!(
                "trusted public key is not base64url: {err}"
            ))
        })?;
    let signature_bytes = decode_signature_value(&signature.value)?;
    let public_key = PublicKey::from_slice(&public_key_bytes).map_err(|err| {
        AttestationError::InvalidArtifactSignature(format!("invalid public key: {err}"))
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|err| {
        AttestationError::InvalidArtifactSignature(format!("invalid signature bytes: {err}"))
    })?;
    let payload_json = canonical_json(payload)?;

    public_key
        .verify(payload_json.as_bytes(), &signature)
        .map_err(|err| AttestationError::InvalidArtifactSignature(err.to_string()))
}

fn trusted_signing_key<'a>(
    signature: &ArtifactSignature,
    trusted_signing_keys: &'a [TrustedSigningKey],
) -> Option<&'a TrustedSigningKey> {
    trusted_signing_keys
        .iter()
        .find(|key| signature.signer == key.signer && signature.key_id == key.key_id)
}

fn decode_signature_value(value: &str) -> Result<Vec<u8>> {
    let encoded = value.strip_prefix("base64url:").unwrap_or(value);
    URL_SAFE_NO_PAD.decode(encoded).map_err(|err| {
        AttestationError::InvalidArtifactSignature(format!("signature is not base64url: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_signing_key_fails_closed() {
        let signature = ArtifactSignature {
            signer: "unknown".into(),
            key_id: "unknown".into(),
            alg: "ed25519".into(),
            value: "base64url:ULskkFC98v_FXOt4lBLINcrVnPoMjMOd_Aj4NpvMaqiBxcU-O9ydZ3JgxxBWmnA74vPoKQEgNcmvRmxJJc5nAA".into(),
        };

        assert!(matches!(
            verify_artifact_signature(&signature, &json!({"x": 1})),
            Err(AttestationError::UnknownArtifactSigningKey { .. })
        ));
    }
}
