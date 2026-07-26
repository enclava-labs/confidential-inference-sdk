use crate::{AttestationError, GpuTeeKind, NvidiaGpuAttestationEvidence, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{self, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NVIDIA_NRAS_ISSUER: &str = "https://nras.attestation.nvidia.com";
pub const NVIDIA_NRAS_CLAIMS_VERSION: &str = "3.0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvidiaGpuAttestationVerificationRequest<'a> {
    pub evidence: &'a NvidiaGpuAttestationEvidence,
    pub expected_nonce: &'a str,
    pub expected_tee: GpuTeeKind,
    pub provider: &'a str,
    pub route_id: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGpuAttestation {
    pub tee: GpuTeeKind,
    pub nonce: String,
    pub attestation_format: String,
    pub verifier: String,
}

impl VerifiedGpuAttestation {
    pub fn nvidia_cc(
        nonce: impl Into<String>,
        attestation_format: impl Into<String>,
        verifier: impl Into<String>,
    ) -> Self {
        Self {
            tee: GpuTeeKind::NvidiaCc,
            nonce: nonce.into(),
            attestation_format: attestation_format.into(),
            verifier: verifier.into(),
        }
    }
}

pub trait GpuAttestationVerifier: Send + Sync {
    fn verify_nvidia_gpu_attestation(
        &self,
        request: &NvidiaGpuAttestationVerificationRequest<'_>,
    ) -> Result<VerifiedGpuAttestation>;
}

#[derive(Clone, Debug, Default)]
pub struct FailClosedGpuAttestationVerifier;

impl GpuAttestationVerifier for FailClosedGpuAttestationVerifier {
    fn verify_nvidia_gpu_attestation(
        &self,
        _request: &NvidiaGpuAttestationVerificationRequest<'_>,
    ) -> Result<VerifiedGpuAttestation> {
        Err(AttestationError::InvalidEvidence(
            "NVIDIA GPU attestation verification backend is not configured".into(),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct NvidiaNrasJwtVerifier {
    jwks: Value,
    issuer: String,
    required_claims_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNvidiaNrasJwt {
    pub nonce: String,
    pub issuer: String,
    pub key_id: Option<String>,
    pub claims_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

impl NvidiaNrasJwtVerifier {
    pub fn from_jwks_json(jwks_json: &str) -> Result<Self> {
        Self::from_jwks_json_with_issuer(jwks_json, NVIDIA_NRAS_ISSUER)
    }

    pub fn from_jwks_json_with_issuer(jwks_json: &str, issuer: impl Into<String>) -> Result<Self> {
        Self::from_jwks_json_with_issuer_and_claims_version(
            jwks_json,
            issuer,
            NVIDIA_NRAS_CLAIMS_VERSION,
        )
    }

    pub fn from_jwks_json_with_issuer_and_claims_version(
        jwks_json: &str,
        issuer: impl Into<String>,
        required_claims_version: impl Into<String>,
    ) -> Result<Self> {
        let jwks: Value = serde_json::from_str(jwks_json)?;
        validate_jwks_shape(&jwks)?;
        let required_claims_version = required_claims_version.into();
        if required_claims_version.trim().is_empty() {
            return Err(AttestationError::InvalidEvidence(
                "required NRAS claims version is empty".into(),
            ));
        }
        Ok(Self {
            jwks,
            issuer: issuer.into(),
            required_claims_version,
        })
    }

    pub fn verify_token(&self, token: &str, expected_nonce: &str) -> Result<VerifiedNvidiaNrasJwt> {
        verify_nvidia_nras_jwt_with_jwks(
            token,
            &self.jwks,
            expected_nonce,
            &self.issuer,
            &self.required_claims_version,
        )
    }
}

impl GpuAttestationVerifier for NvidiaNrasJwtVerifier {
    fn verify_nvidia_gpu_attestation(
        &self,
        request: &NvidiaGpuAttestationVerificationRequest<'_>,
    ) -> Result<VerifiedGpuAttestation> {
        if request.expected_tee != GpuTeeKind::NvidiaCc {
            return Err(AttestationError::InvalidEvidence(
                "NVIDIA NRAS verifier can only verify nvidia_cc GPU TEE evidence".into(),
            ));
        }
        let token = request.evidence.nras_token.as_deref().ok_or_else(|| {
            AttestationError::InvalidEvidence(
                "NVIDIA GPU attestation evidence is missing NRAS token".into(),
            )
        })?;
        let verified = self.verify_token(token, request.expected_nonce)?;
        Ok(VerifiedGpuAttestation::nvidia_cc(
            verified.nonce,
            request.evidence.attestation_format.clone(),
            verified
                .key_id
                .map(|kid| format!("nvidia-nras-jwt:{kid}"))
                .unwrap_or_else(|| "nvidia-nras-jwt".into()),
        ))
    }
}

pub fn verify_nvidia_nras_jwt_with_jwks_json(
    token: &str,
    jwks_json: &str,
    expected_nonce: &str,
) -> Result<VerifiedNvidiaNrasJwt> {
    let verifier = NvidiaNrasJwtVerifier::from_jwks_json(jwks_json)?;
    verifier.verify_token(token, expected_nonce)
}

fn verify_nvidia_nras_jwt_with_jwks(
    token: &str,
    jwks: &Value,
    expected_nonce: &str,
    expected_issuer: &str,
    expected_claims_version: &str,
) -> Result<VerifiedNvidiaNrasJwt> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AttestationError::InvalidEvidence(
            "NRAS token is not a compact JWT".into(),
        ));
    }
    let header_bytes = base64url_decode(parts[0], "JWT header")?;
    let claims_bytes = base64url_decode(parts[1], "JWT claims")?;
    let signature = base64url_decode(parts[2], "JWT signature")?;
    if signature.len() != 96 {
        return Err(AttestationError::InvalidEvidence(format!(
            "NRAS ES384 signature has wrong size: {} bytes",
            signature.len()
        )));
    }

    let header: JwtHeader = serde_json::from_slice(&header_bytes)?;
    if header.alg != "ES384" {
        return Err(AttestationError::InvalidEvidence(format!(
            "unsupported NRAS JWT alg {}",
            header.alg
        )));
    }
    let jwk = select_jwk(jwks, header.kid.as_deref())?;
    let public_key = p384_public_key_from_jwk(jwk)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, public_key)
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AttestationError::InvalidEvidence("NRAS JWT signature is invalid".into()))?;

    let claims: Value = serde_json::from_slice(&claims_bytes)?;
    let issuer = string_claim(&claims, "iss")?;
    if issuer != expected_issuer {
        return Err(AttestationError::InvalidEvidence(format!(
            "NRAS JWT issuer {issuer} does not match expected issuer {expected_issuer}"
        )));
    }
    let nonce = string_claim(&claims, "eat_nonce")?;
    if nonce != expected_nonce {
        return Err(AttestationError::InvalidEvidence(
            "NRAS JWT nonce does not match expected nonce".into(),
        ));
    }
    let claims_version = string_claim(&claims, "x-nvidia-ver")?;
    if claims_version != expected_claims_version {
        return Err(AttestationError::InvalidEvidence(format!(
            "NRAS JWT claims version {claims_version} does not match requested version {expected_claims_version}"
        )));
    }
    let overall = claims
        .get("x-nvidia-overall-att-result")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            AttestationError::InvalidEvidence(
                "NRAS JWT missing x-nvidia-overall-att-result boolean claim".into(),
            )
        })?;
    if !overall {
        return Err(AttestationError::InvalidEvidence(
            "NRAS JWT overall attestation result is false".into(),
        ));
    }
    validate_optional_time_claim(&claims, "nbf", |claim, now| claim <= now)?;
    validate_optional_time_claim(&claims, "exp", |claim, now| claim > now)?;

    Ok(VerifiedNvidiaNrasJwt {
        nonce: nonce.into(),
        issuer: issuer.into(),
        key_id: header.kid,
        claims_version: Some(claims_version.to_owned()),
    })
}

fn validate_jwks_shape(jwks: &Value) -> Result<()> {
    let keys = jwks.get("keys").and_then(Value::as_array).ok_or_else(|| {
        AttestationError::InvalidEvidence("NRAS JWKS is missing keys array".into())
    })?;
    if keys.is_empty() {
        return Err(AttestationError::InvalidEvidence(
            "NRAS JWKS has no keys".into(),
        ));
    }
    Ok(())
}

fn select_jwk<'a>(jwks: &'a Value, kid: Option<&str>) -> Result<&'a Value> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| AttestationError::InvalidEvidence("NRAS JWKS has no keys".into()))?;
    match kid {
        Some(kid) => keys
            .iter()
            .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
            .ok_or_else(|| {
                AttestationError::InvalidEvidence(format!("NRAS JWKS has no key for kid {kid}"))
            }),
        None if keys.len() == 1 => Ok(&keys[0]),
        None => Err(AttestationError::InvalidEvidence(
            "NRAS JWT header missing kid while JWKS has multiple keys".into(),
        )),
    }
}

fn p384_public_key_from_jwk(jwk: &Value) -> Result<Vec<u8>> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC") {
        return Err(AttestationError::InvalidEvidence(
            "NRAS JWK is not an EC key".into(),
        ));
    }
    if jwk.get("crv").and_then(Value::as_str) != Some("P-384") {
        return Err(AttestationError::InvalidEvidence(
            "NRAS JWK is not a P-384 key".into(),
        ));
    }
    if let Some(alg) = jwk.get("alg").and_then(Value::as_str) {
        if alg != "ES384" {
            return Err(AttestationError::InvalidEvidence(format!(
                "NRAS JWK alg {alg} is not ES384"
            )));
        }
    }
    let x = base64url_decode(string_claim(jwk, "x")?, "JWK x coordinate")?;
    let y = base64url_decode(string_claim(jwk, "y")?, "JWK y coordinate")?;
    if x.len() != 48 || y.len() != 48 {
        return Err(AttestationError::InvalidEvidence(
            "NRAS P-384 JWK coordinates must be 48 bytes".into(),
        ));
    }
    let mut public_key = Vec::with_capacity(97);
    public_key.push(0x04);
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);
    Ok(public_key)
}

fn string_claim<'a>(claims: &'a Value, name: &str) -> Result<&'a str> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AttestationError::InvalidEvidence(format!("NRAS JWT missing {name} claim")))
}

fn validate_optional_time_claim(
    claims: &Value,
    name: &str,
    valid: impl FnOnce(u64, u64) -> bool,
) -> Result<()> {
    let Some(claim) = claims.get(name) else {
        return Ok(());
    };
    let claim = claim.as_u64().ok_or_else(|| {
        AttestationError::InvalidEvidence(format!("NRAS JWT {name} claim is not an integer"))
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            AttestationError::InvalidEvidence(format!("system time is before UNIX epoch: {error}"))
        })?
        .as_secs();
    if valid(claim, now) {
        Ok(())
    } else {
        Err(AttestationError::InvalidEvidence(format!(
            "NRAS JWT {name} claim is not valid at current time"
        )))
    }
}

fn base64url_decode(value: &str, field: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        AttestationError::InvalidEvidence(format!("{field} is not base64url: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};
    use serde_json::json;

    #[test]
    fn nvidia_nras_jwt_verifier_accepts_es384_token_with_matching_nonce() {
        let fixture = SignedNrasTokenFixture::new(true);
        let verifier = NvidiaNrasJwtVerifier::from_jwks_json(&fixture.jwks.to_string()).unwrap();

        let verified = verifier
            .verify_token(&fixture.token, &fixture.nonce)
            .unwrap();

        assert_eq!(verified.nonce, fixture.nonce);
        assert_eq!(verified.issuer, NVIDIA_NRAS_ISSUER);
        assert_eq!(verified.key_id.as_deref(), Some("nras-test-key"));
        assert_eq!(
            verified.claims_version.as_deref(),
            Some(NVIDIA_NRAS_CLAIMS_VERSION)
        );
    }

    #[test]
    fn nvidia_nras_jwt_verifier_rejects_unrequested_claims_version() {
        let fixture = SignedNrasTokenFixture::new_with_claims_version(true, "2.0");
        let verifier = NvidiaNrasJwtVerifier::from_jwks_json(&fixture.jwks.to_string()).unwrap();

        let error = verifier
            .verify_token(&fixture.token, &fixture.nonce)
            .unwrap_err();

        assert!(error.to_string().contains("claims version"));
    }

    #[test]
    fn nvidia_nras_jwt_verifier_rejects_wrong_nonce() {
        let fixture = SignedNrasTokenFixture::new(true);
        let verifier = NvidiaNrasJwtVerifier::from_jwks_json(&fixture.jwks.to_string()).unwrap();

        let error = verifier
            .verify_token(&fixture.token, &"44".repeat(32))
            .unwrap_err();

        assert!(error.to_string().contains("nonce"));
    }

    #[test]
    fn nvidia_nras_jwt_verifier_rejects_failed_overall_result() {
        let fixture = SignedNrasTokenFixture::new(false);
        let verifier = NvidiaNrasJwtVerifier::from_jwks_json(&fixture.jwks.to_string()).unwrap();

        let error = verifier
            .verify_token(&fixture.token, &fixture.nonce)
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("overall attestation result is false"));
    }

    #[test]
    fn nvidia_nras_jwt_verifier_rejects_tampered_signature() {
        let mut fixture = SignedNrasTokenFixture::new(true);
        fixture.token.push('x');
        let verifier = NvidiaNrasJwtVerifier::from_jwks_json(&fixture.jwks.to_string()).unwrap();

        let error = verifier
            .verify_token(&fixture.token, &fixture.nonce)
            .unwrap_err();

        assert!(error.to_string().contains("signature"));
    }

    #[test]
    fn nvidia_nras_jwt_verifier_satisfies_gpu_attestation_trait() {
        let fixture = SignedNrasTokenFixture::new(true);
        let verifier = NvidiaNrasJwtVerifier::from_jwks_json(&fixture.jwks.to_string()).unwrap();
        let evidence = NvidiaGpuAttestationEvidence {
            schema: NvidiaGpuAttestationEvidence::SCHEMA.into(),
            attestation_format: NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3.into(),
            nonce: fixture.nonce.clone(),
            arch: Some("HOPPER".into()),
            payload_sha256: Some("sha256:nvidia-payload".into()),
            raw_payload_base64: Some("e30".into()),
            nras_token: Some(fixture.token),
        };

        let verified = verifier
            .verify_nvidia_gpu_attestation(&NvidiaGpuAttestationVerificationRequest {
                evidence: &evidence,
                expected_nonce: &fixture.nonce,
                expected_tee: GpuTeeKind::NvidiaCc,
                provider: "redpill-fixture",
                route_id: "redpill-fixture:gpt-oss-120b:private",
            })
            .unwrap();

        assert_eq!(verified.tee, GpuTeeKind::NvidiaCc);
        assert_eq!(verified.nonce, fixture.nonce);
        assert_eq!(
            verified.attestation_format,
            NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3
        );
        assert_eq!(verified.verifier, "nvidia-nras-jwt:nras-test-key");
    }

    struct SignedNrasTokenFixture {
        nonce: String,
        token: String,
        jwks: Value,
    }

    impl SignedNrasTokenFixture {
        fn new(overall_result: bool) -> Self {
            Self::new_with_claims_version(overall_result, NVIDIA_NRAS_CLAIMS_VERSION)
        }

        fn new_with_claims_version(overall_result: bool, claims_version: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
            let key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let public_key = key_pair.public_key().as_ref();
            assert_eq!(public_key[0], 0x04);
            let x = URL_SAFE_NO_PAD.encode(&public_key[1..49]);
            let y = URL_SAFE_NO_PAD.encode(&public_key[49..97]);
            let jwks = json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-384",
                    "alg": "ES384",
                    "kid": "nras-test-key",
                    "x": x,
                    "y": y
                }]
            });

            let nonce = "33".repeat(32);
            let header = json!({
                "alg": "ES384",
                "typ": "JWT",
                "kid": "nras-test-key"
            });
            let claims = json!({
                "iss": NVIDIA_NRAS_ISSUER,
                "sub": "nvidia-gpu",
                "x-nvidia-ver": claims_version,
                "x-nvidia-overall-att-result": overall_result,
                "eat_nonce": nonce,
                "nbf": 0u64,
                "exp": 4_070_908_800u64
            });
            let signing_input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            );
            let signature = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();
            let token = format!(
                "{}.{}",
                signing_input,
                URL_SAFE_NO_PAD.encode(signature.as_ref())
            );

            Self { nonce, token, jwks }
        }
    }
}
