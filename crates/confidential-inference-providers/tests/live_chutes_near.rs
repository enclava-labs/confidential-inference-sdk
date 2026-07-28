use base64::Engine;
use confidential_inference_attestation::{
    certificate_spki_sha256_hex, verify_chutes_live_report_data_binding, AliasConfidence,
    BoundDataRequirement, ChannelBindingKind, ChutesLiveEvidence, ChutesLiveReportDataBinding,
    FreshnessClass, GpuAttestationVerifier, GpuTeeKind, NearLiveEvidence,
    NvidiaGpuAttestationEvidence, NvidiaGpuAttestationVerificationRequest,
    ResponseIntegrityRequirement, TinfoilQuoteVerifier, TrustTier,
};
use confidential_inference_providers::{
    ChutesHttpProvider, DcapTdxCollateralResolver, EncryptionRequirement, EvidenceRequest,
    NearHttpProvider, NvidiaNrasRemoteClient, ProviderAdapter, RouteDefinition, RouteLifecycle,
    StreamingSupport,
};
use sha2::{Digest, Sha256};

const TEST_NONCE: &str = "70f50e57af3d2c7c9cff22332799be4ca67f2bf6f2b77e63db834e0434ad30e6";

fn credential(name: &str) -> String {
    if let Ok(value) = std::env::var(name) {
        return value;
    }
    let dotenv_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.env");
    let dotenv = std::fs::read_to_string(dotenv_path).expect("missing workspace .env");
    dotenv
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (candidate, value) = line.split_once('=')?;
            (candidate.trim() == name).then(|| {
                value
                    .trim()
                    .trim_matches(|character| character == '\'' || character == '"')
                    .to_owned()
            })
        })
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("{name} must be configured in the environment or .env"))
}

fn chutes_route() -> RouteDefinition {
    RouteDefinition {
        route_id: "chutes:qwen3-32b-tee:live".into(),
        route_status: RouteLifecycle::Active,
        provider: "chutes".into(),
        provider_model: "Qwen/Qwen3-32B-TEE".into(),
        evidence_family: "chutes_live_e2ee".into(),
        api_base_url: "https://llm.chutes.ai/v1".into(),
        evidence_endpoint: "https://api.chutes.ai".into(),
        adapter_version: "chutes-live-v1".into(),
        freshness_class: FreshnessClass::PerRequest,
        channel_binding_kind: ChannelBindingKind::AttestedAppE2ee,
        trust_tier: TrustTier::AppE2ee,
        request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
        accepted_gpu_tees: vec![GpuTeeKind::NvidiaCc],
        request_encryption: EncryptionRequirement::Required,
        response_decryption: EncryptionRequirement::Required,
        streaming: StreamingSupport::Unsupported,
        alias_confidence: AliasConfidence::ProviderDeclared,
    }
}

fn near_route() -> RouteDefinition {
    RouteDefinition {
        route_id: "near:gpt-oss-120b:live".into(),
        route_status: RouteLifecycle::Active,
        provider: "near".into(),
        provider_model: "openai/gpt-oss-120b".into(),
        evidence_family: "near_hw_verified_tls".into(),
        api_base_url: "https://gpt-oss-120b.completions.near.ai/v1".into(),
        evidence_endpoint: "https://gpt-oss-120b.completions.near.ai/v1/attestation/report".into(),
        adapter_version: "near-live-v1".into(),
        freshness_class: FreshnessClass::PerRequest,
        channel_binding_kind: ChannelBindingKind::TeeTerminatedTls,
        trust_tier: TrustTier::HwVerifiedTls,
        request_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_confidentiality_requirement: BoundDataRequirement::BoundToAttestedWorkload,
        response_integrity_requirement: ResponseIntegrityRequirement::ChannelBound,
        accepted_gpu_tees: vec![GpuTeeKind::NvidiaCc],
        request_encryption: EncryptionRequirement::NotRequired,
        response_decryption: EncryptionRequirement::NotRequired,
        streaming: StreamingSupport::Unsupported,
        alias_confidence: AliasConfidence::ProviderDeclared,
    }
}

fn request(model: &str) -> EvidenceRequest {
    EvidenceRequest {
        requested_model: model.into(),
        policy_digest: "sha256:live-smoke-test".into(),
        nonce: Some(TEST_NONCE.into()),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

async fn verify_nras_token(
    evidence: &NvidiaGpuAttestationEvidence,
    provider: &str,
    route_id: &str,
) {
    let verifier = NvidiaNrasRemoteClient::with_default_http()
        .unwrap()
        .fetch_jwt_verifier()
        .await
        .unwrap();
    let verified = verifier
        .verify_nvidia_gpu_attestation(&NvidiaGpuAttestationVerificationRequest {
            evidence,
            expected_nonce: &evidence.nonce,
            expected_tee: GpuTeeKind::NvidiaCc,
            provider,
            route_id,
        })
        .unwrap();
    assert_eq!(verified.tee, GpuTeeKind::NvidiaCc);
    assert_eq!(verified.nonce, evidence.nonce);
}

#[tokio::test]
#[ignore = "requires CHUTES_API_KEY and live provider/NRAS network access"]
async fn chutes_live_adapter_captures_bound_evidence() {
    let route = chutes_route();
    let api_key = credential("CHUTES_API_KEY");
    let provider = ChutesHttpProvider::new("chutes", vec![route.clone()], api_key).unwrap();

    let raw = provider
        .fetch_evidence(&route, &request("Qwen/Qwen3-32B-TEE"))
        .await
        .unwrap();
    let evidence: ChutesLiveEvidence = serde_json::from_slice(&raw).unwrap();

    assert_eq!(evidence.schema, ChutesLiveEvidence::SCHEMA);
    assert_eq!(evidence.request_nonce, TEST_NONCE);
    assert_eq!(evidence.route_id, route.route_id);
    assert_eq!(evidence.e2e_public_key_base64.len(), 1_580);
    let quote = base64::engine::general_purpose::STANDARD
        .decode(&evidence.quote_base64)
        .unwrap();
    assert!(quote.len() > 4_000);
    let gpu_attestation = evidence.gpu_attestation.as_ref().unwrap();
    assert!(gpu_attestation.nras_token.is_some());
    verify_nras_token(gpu_attestation, &route.provider, &route.route_id).await;

    let verifier = DcapTdxCollateralResolver::with_phala_pccs()
        .unwrap()
        .verifier_for_quote(&quote)
        .await
        .unwrap();
    let verified_quote = verifier.verify_tdx_quote(&quote).unwrap();
    assert_eq!(verified_quote.report_data.len(), 128);
    assert_eq!(verified_quote.mr_td.len(), 96);
    let certificate = base64::engine::general_purpose::STANDARD
        .decode(&evidence.certificate_der_base64)
        .unwrap();
    let certificate_spki = certificate_spki_sha256_hex(&certificate).unwrap();
    assert_eq!(
        verify_chutes_live_report_data_binding(
            &verified_quote.report_data,
            &evidence.request_nonce,
            &evidence.e2e_public_key_base64,
            &certificate_spki,
        ),
        ChutesLiveReportDataBinding::Verified
    );
}

#[tokio::test]
#[ignore = "requires NEAR_API_KEY and live provider/NRAS network access"]
async fn near_live_adapter_captures_tls_bound_evidence() {
    let route = near_route();
    let api_key = credential("NEAR_API_KEY");
    let provider = NearHttpProvider::new("near", vec![route.clone()], api_key).unwrap();

    let raw = provider
        .fetch_evidence(&route, &request("openai/gpt-oss-120b"))
        .await
        .unwrap();
    let evidence: NearLiveEvidence = serde_json::from_slice(&raw).unwrap();

    assert_eq!(evidence.schema, NearLiveEvidence::SCHEMA);
    assert_eq!(evidence.request_nonce, TEST_NONCE);
    assert_eq!(evidence.route_id, route.route_id);
    assert_eq!(evidence.live_tls_spki_sha256.len(), 64);
    let live_certificate = base64::engine::general_purpose::STANDARD
        .decode(&evidence.live_tls_leaf_certificate_der_base64)
        .unwrap();
    assert!(live_certificate.len() > 500);
    let gpu_attestation = evidence.gpu_attestation.as_ref().unwrap();
    assert!(gpu_attestation.nras_token.is_some());
    verify_nras_token(gpu_attestation, &route.provider, &route.route_id).await;

    let raw_attestation = base64::engine::general_purpose::STANDARD
        .decode(&evidence.raw_attestation_body_base64)
        .unwrap();
    let raw_attestation: serde_json::Value = serde_json::from_slice(&raw_attestation).unwrap();
    let quote = decode_hex(raw_attestation["intel_quote"].as_str().unwrap());
    let verifier = DcapTdxCollateralResolver::with_phala_pccs()
        .unwrap()
        .verifier_for_quote(&quote)
        .await
        .unwrap();
    let verified_quote = verifier.verify_tdx_quote(&quote).unwrap();
    assert_eq!(&verified_quote.report_data[64..], TEST_NONCE);
    assert!(verified_quote.mr_config_id.starts_with("01"));
    assert_eq!(
        raw_attestation["tls_cert_fingerprint"].as_str().unwrap(),
        evidence.live_tls_spki_sha256
    );
    let signing_address = decode_hex(
        raw_attestation["signing_address"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    );
    let mut binding_input = signing_address;
    binding_input.extend_from_slice(&decode_hex(&evidence.live_tls_spki_sha256));
    assert_eq!(
        decode_hex(&verified_quote.report_data)[..32],
        Sha256::digest(binding_input)[..]
    );
}
