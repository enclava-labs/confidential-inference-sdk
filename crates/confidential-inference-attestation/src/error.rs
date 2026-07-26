use thiserror::Error;

pub type Result<T> = std::result::Result<T, AttestationError>;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("canonical JSON does not permit floating point numbers")]
    NonCanonicalFloat,

    #[error("JSON integer {0} exceeds the cross-language safe integer limit")]
    UnsafeInteger(u64),

    #[error("invalid fixture evidence: {0}")]
    InvalidEvidence(String),

    #[error("ACI evidence is invalid: {0}")]
    InvalidAciEvidence(String),

    #[error("invalid X.509 certificate: {0}")]
    InvalidCertificate(String),

    #[error("reference values are missing provider {provider}")]
    MissingProviderReference { provider: String },

    #[error("reference values are missing route {route_id}")]
    MissingRouteReference { route_id: String },

    #[error("reference-values envelope signature metadata is incomplete")]
    InvalidReferenceSignature,

    #[error("artifact envelope signature is invalid: {0}")]
    InvalidArtifactSignature(String),

    #[error("unsupported artifact signature algorithm {0}")]
    UnsupportedSignatureAlgorithm(String),

    #[error("unknown artifact signing key {signer}/{key_id}")]
    UnknownArtifactSigningKey { signer: String, key_id: String },

    #[error("provider registry is invalid: {0}")]
    InvalidProviderRegistry(String),

    #[error("provider registry update is invalid: {0}")]
    InvalidRegistryUpdate(String),

    #[error("provider registry update would weaken security: {0}")]
    WeakeningRegistryUpdate(String),

    #[error("reference values update is invalid: {0}")]
    InvalidReferenceValuesUpdate(String),

    #[error("reference values update would weaken security: {0}")]
    WeakeningReferenceValuesUpdate(String),

    #[error("verification policy is invalid: {0}")]
    InvalidPolicy(String),

    #[error("verdict summary conflicts with check map: {0}")]
    MalformedVerdict(String),
}
