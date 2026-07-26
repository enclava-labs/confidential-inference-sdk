use crate::{
    AttestationError, ChannelBindingKind, CpuTeeKind, DstackTcbInfo, GpuTeeKind, Result,
    TdxQuoteMeasurements,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub kind: String,
    pub name: String,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadImage {
    pub service: String,
    pub reference: String,
    pub digest: String,
}

impl WorkloadImage {
    pub fn is_digest_pinned(&self) -> bool {
        let Some(hex) = self.digest.strip_prefix("sha256:") else {
            return false;
        };
        !self.service.trim().is_empty()
            && hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && self.reference.ends_with(&format!("@{}", self.digest))
    }
}

/// Parses every image in a dstack compose document into a canonical, complete
/// digest-pinned workload manifest. Compose service definitions are treated as
/// authoritative; legacy flat documents are walked recursively for `image`
/// fields so older provider responses remain verifiable.
pub fn parse_dstack_workload_images(app_compose: &str) -> Result<Vec<WorkloadImage>> {
    let document: serde_yaml::Value = serde_yaml::from_str(app_compose).map_err(|error| {
        AttestationError::InvalidEvidence(format!("dstack app_compose is not valid YAML: {error}"))
    })?;
    let mut raw_images = Vec::new();

    if let serde_yaml::Value::Mapping(root) = &document {
        let services_key = serde_yaml::Value::String("services".into());
        if let Some(services) = root.get(&services_key) {
            let services = services.as_mapping().ok_or_else(|| {
                AttestationError::InvalidEvidence(
                    "dstack app_compose services is not a mapping".into(),
                )
            })?;
            for (service, config) in services {
                let service = service
                    .as_str()
                    .filter(|name| !name.trim().is_empty())
                    .ok_or_else(|| {
                        AttestationError::InvalidEvidence(
                            "dstack compose has an invalid service name".into(),
                        )
                    })?;
                let config = config.as_mapping().ok_or_else(|| {
                    AttestationError::InvalidEvidence(format!(
                        "dstack compose service {service} is not a mapping"
                    ))
                })?;
                let image_key = serde_yaml::Value::String("image".into());
                let image = config
                    .get(&image_key)
                    .and_then(serde_yaml::Value::as_str)
                    .ok_or_else(|| {
                        AttestationError::InvalidEvidence(format!(
                            "dstack compose service {service} has no digest-pinned image"
                        ))
                    })?;
                raw_images.push((service.to_owned(), image.to_owned()));
            }
        } else {
            collect_dstack_image_fields(&document, "root", &mut raw_images)?;
        }
    } else {
        collect_dstack_image_fields(&document, "root", &mut raw_images)?;
    }

    let mut images = raw_images
        .into_iter()
        .map(|(service, reference)| parse_digest_pinned_image(service, &reference))
        .collect::<Result<Vec<_>>>()?;
    images.sort();
    if images
        .windows(2)
        .any(|pair| pair[0].service == pair[1].service)
    {
        return Err(AttestationError::InvalidEvidence(
            "dstack compose repeats a workload image service".into(),
        ));
    }
    Ok(images)
}

fn collect_dstack_image_fields(
    value: &serde_yaml::Value,
    path: &str,
    images: &mut Vec<(String, String)>,
) -> Result<()> {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, value) in mapping {
                let key = key.as_str().unwrap_or("<non-string>");
                if key == "image" {
                    let image = value.as_str().ok_or_else(|| {
                        AttestationError::InvalidEvidence(format!(
                            "dstack compose image at {path} is not a string"
                        ))
                    })?;
                    images.push((path.to_owned(), image.to_owned()));
                } else {
                    collect_dstack_image_fields(value, &format!("{path}.{key}"), images)?;
                }
            }
        }
        serde_yaml::Value::Sequence(sequence) => {
            for (index, value) in sequence.iter().enumerate() {
                collect_dstack_image_fields(value, &format!("{path}[{index}]"), images)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_digest_pinned_image(service: String, reference: &str) -> Result<WorkloadImage> {
    let reference = reference.trim();
    let (repository, digest_hex) = reference.rsplit_once("@sha256:").ok_or_else(|| {
        AttestationError::InvalidEvidence(format!(
            "dstack compose service {service} image is not pinned by sha256 digest"
        ))
    })?;
    if repository.trim().is_empty()
        || digest_hex.len() != 64
        || !digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AttestationError::InvalidEvidence(format!(
            "dstack compose service {service} has an invalid sha256 image digest"
        )));
    }
    let digest = format!("sha256:{digest_hex}");
    Ok(WorkloadImage {
        service,
        reference: format!("{repository}@{digest}"),
        digest,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceHardware {
    pub cpu: CpuTeeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuTeeKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvidiaGpuAttestationEvidence {
    pub schema: String,
    pub attestation_format: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_payload_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nras_token: Option<String>,
}

impl NvidiaGpuAttestationEvidence {
    pub const SCHEMA: &'static str = "confidential-inference.nvidia-gpu-attestation.v1";
    pub const NRAS_GPU_EVIDENCE_V3: &'static str = "nvidia.nras.gpu-evidence.v3";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelBindingEvidence {
    pub kind: ChannelBindingKind,
    pub public_key_digest: String,
    pub request_bound: bool,
    pub response_bound: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureEvidence {
    pub schema: String,
    pub provider: String,
    pub route_id: String,
    pub evidence_family: String,
    pub tee_measurement: String,
    pub hardware: EvidenceHardware,
    pub channel_binding: ChannelBindingEvidence,
    pub attested_model: String,
    pub workload_image_digest: String,
    pub model_artifacts: Vec<ArtifactDigest>,
    pub issued_at: String,
    pub expires_at: String,
    pub expires_at_epoch_ms: u64,
}

impl FixtureEvidence {
    pub const SCHEMA: &'static str = "confidential-inference.fixture-evidence.v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TinfoilTlsEvidence {
    pub schema: String,
    pub provider: String,
    pub route_id: String,
    pub evidence_family: String,
    pub tee_measurement: String,
    pub hardware: EvidenceHardware,
    pub report_data: String,
    pub leaf_certificate_der_base64: String,
    pub attested_model: String,
    pub workload_image_digest: String,
    pub model_artifacts: Vec<ArtifactDigest>,
    pub issued_at: String,
    pub expires_at: String,
    pub expires_at_epoch_ms: u64,
}

impl TinfoilTlsEvidence {
    pub const SCHEMA: &'static str = "confidential-inference.tinfoil-tls-evidence.v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChutesE2eeEvidence {
    pub schema: String,
    pub provider: String,
    pub route_id: String,
    pub evidence_family: String,
    pub tee_measurement: String,
    pub hardware: EvidenceHardware,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_attestation: Option<NvidiaGpuAttestationEvidence>,
    pub report_data: String,
    pub nonce: String,
    #[serde(rename = "e2e_pubkey", alias = "e2e_public_key")]
    pub e2e_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_model: Option<String>,
    pub workload_image_digest: String,
    pub model_artifacts: Vec<ArtifactDigest>,
    pub issued_at: String,
    pub expires_at: String,
    pub expires_at_epoch_ms: u64,
}

impl ChutesE2eeEvidence {
    pub const SCHEMA: &'static str = "confidential-inference.chutes-e2ee-evidence.v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IonetConfidentialEvidence {
    pub schema: String,
    pub provider: String,
    pub route_id: String,
    pub evidence_family: String,
    pub nonce: String,
    pub nonce_prefix: String,
    pub signing_address: String,
    pub image_digest: String,
    pub gpu_tee: GpuTeeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_attestation: Option<NvidiaGpuAttestationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_quote_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_model: Option<String>,
    pub workload_image_digest: String,
    pub model_artifacts: Vec<ArtifactDigest>,
    pub issued_at: String,
    pub expires_at: String,
    pub expires_at_epoch_ms: u64,
}

impl IonetConfidentialEvidence {
    pub const SCHEMA: &'static str = "confidential-inference.ionet-confidential-evidence.v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TinfoilLiveCaptureEvidence {
    pub schema: String,
    pub provider: String,
    pub route_id: String,
    pub evidence_family: String,
    pub requested_model: String,
    pub policy_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub evidence_endpoint: String,
    pub live_tls_spki_sha256: String,
    pub live_tls_leaf_certificate_der_base64: String,
    pub raw_attestation_body_base64: String,
}

impl TinfoilLiveCaptureEvidence {
    pub const SCHEMA: &'static str = "confidential-inference.tinfoil-live-capture.v1";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DstackEvidence {
    pub schema: String,
    pub provider: String,
    pub route_id: String,
    pub evidence_family: String,
    pub tee_measurement: String,
    pub hardware: EvidenceHardware,
    pub quote_measurements: TdxQuoteMeasurements,
    pub tcb_info: DstackTcbInfo,
    pub channel_binding: ChannelBindingEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_model: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workload_images: Vec<WorkloadImage>,
    pub workload_image_digest: String,
    pub model_artifacts: Vec<ArtifactDigest>,
    pub issued_at: String,
    pub expires_at: String,
    pub expires_at_epoch_ms: u64,
}

impl DstackEvidence {
    pub const SCHEMA: &'static str = "confidential-inference.dstack-evidence.v1";
}
