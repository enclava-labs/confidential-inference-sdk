use crate::{
    certificate_spki_sha256_hex, certificate_validity_epoch_millis, near_live_tee_measurement,
    parse_utc_timestamp_millis, sha256_digest, AttestationError, GpuAttestationVerifier,
    GpuTeeKind, NvidiaGpuAttestationEvidence, NvidiaGpuAttestationVerificationRequest,
    RedpillAciLiveEvidence, Result, TinfoilQuoteVerifier, VerifiedTdxQuote,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};

fn invalid(message: &str) -> AttestationError {
    AttestationError::InvalidEvidence(format!("RedPill ACI: {message}"))
}
pub fn redpill_aci_jcs_digest(value: &Value) -> Result<String> {
    Ok(sha256_digest(&serde_json_canonicalizer::to_vec(value)?))
}

pub fn verify_redpill_aci_signature(
    value: &Value,
    public_key: &[u8],
    signature: &[u8],
) -> Result<()> {
    let key = ed25519_compact::PublicKey::from_slice(public_key)
        .map_err(|_| invalid("invalid receipt key"))?;
    let signature = ed25519_compact::Signature::from_slice(signature)
        .map_err(|_| invalid("invalid receipt signature"))?;
    key.verify(serde_json_canonicalizer::to_vec(value)?, &signature)
        .map_err(|_| invalid("receipt signature mismatch"))
}

fn field<'a>(value: &'a Value, path: &str) -> Result<&'a str> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("missing {path}")))
}
fn hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("invalid hex"));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid("invalid hex"))?;
            u8::from_str_radix(text, 16).map_err(|_| invalid("invalid hex"))
        })
        .collect()
}

fn dstack_identity(event_log: &str, quoted_rtmr3: &str) -> Result<(String, String)> {
    let events: Vec<Value> = serde_json::from_str(event_log)?;
    let mut replay = [0u8; 48];
    let mut compose = None;
    let mut app_id = None;
    let mut mr_kms = None;
    let mut key_provider = None;
    for event in events {
        let imr = event
            .get("imr")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("invalid event IMR"))?;
        if imr != 3 {
            continue;
        }
        let event_type = event
            .get("event_type")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| invalid("invalid event type"))?;
        let name = field(&event, "/event")?;
        let payload = hex(field(&event, "/event_payload")?)?;
        let mut hasher = Sha384::new();
        hasher.update(event_type.to_le_bytes());
        hasher.update(b":");
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(&payload);
        let digest = hasher.finalize();
        let supplied = field(&event, "/digest")?;
        if !supplied.is_empty() && hex(supplied)? != digest.as_slice() {
            return Err(invalid("event digest mismatch"));
        }
        let mut extend = Sha384::new();
        extend.update(replay);
        extend.update(digest);
        replay.copy_from_slice(&extend.finalize());
        if event_type == 0x0800_0001 {
            let target = match name {
                "compose-hash" if payload.len() == 32 => Some(&mut compose),
                "app-id" if payload.len() == 20 => Some(&mut app_id),
                "mr-kms" if payload.len() == 32 => Some(&mut mr_kms),
                "key-provider" if !payload.is_empty() => Some(&mut key_provider),
                "compose-hash" | "app-id" | "mr-kms" | "key-provider" => {
                    return Err(invalid("invalid app identity event"));
                }
                _ => None,
            };
            if let Some(target) = target {
                let value = payload
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                if target.replace(value).is_some() {
                    return Err(invalid("duplicate app identity event"));
                }
            }
        }
    }
    if hex(quoted_rtmr3)? != replay {
        return Err(invalid("event log does not match quoted RTMR3"));
    }
    let compose = compose.ok_or_else(|| invalid("missing compose-hash"))?;
    let mr_kms = mr_kms.ok_or_else(|| invalid("missing mr-kms"))?;
    let key_provider = key_provider.ok_or_else(|| invalid("missing key-provider"))?;
    let identity = format!(
        "compose:{compose}:app:{}:kms:{mr_kms}:key_provider:{key_provider}",
        app_id.unwrap_or_default()
    );
    Ok((identity, compose))
}
fn session_evidence(capture: &RedpillAciLiveEvidence) -> Result<Value> {
    if capture.session.get("api_version").and_then(Value::as_str) != Some("aci/1")
        || redpill_aci_jcs_digest(&capture.session)?.strip_prefix("sha256:")
            != Some(capture.session_id.as_str())
    {
        return Err(invalid("session ID does not match canonical session"));
    }
    let data = field(&capture.session, "/evidence/data")?;
    let (header, encoded) = data
        .split_once(',')
        .ok_or_else(|| invalid("invalid session evidence data URI"))?;
    if !header.starts_with("data:") || !header.ends_with(";base64") {
        return Err(invalid("invalid session evidence data URI"));
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| invalid("invalid session evidence base64"))?;
    if sha256_digest(&bytes) != field(&capture.session, "/evidence/digest")? {
        return Err(invalid("session evidence digest mismatch"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn redpill_aci_quote_bytes(capture: &RedpillAciLiveEvidence) -> Result<(Vec<u8>, Vec<u8>)> {
    let model = session_evidence(capture)?;
    Ok((
        hex(field(
            &capture.gateway_report,
            "/attestation/evidence/quote",
        )?)?,
        hex(field(&model, "/intel_quote")?)?,
    ))
}

pub fn redpill_aci_tee_measurement(
    provider_model: &str,
    gateway: &VerifiedTdxQuote,
    model: &VerifiedTdxQuote,
) -> String {
    format!(
        "redpill-aci:model:{provider_model}:gateway:{}:upstream:{}",
        near_live_tee_measurement(gateway),
        near_live_tee_measurement(model)
    )
}

#[derive(Clone, Debug)]
pub struct VerifiedRedpillAciCapture {
    pub tee_measurement: String,
    pub live_tls_spki_sha256: String,
    pub issued_at: String,
    pub expires_at_epoch_ms: u64,
    pub gateway_quote: VerifiedTdxQuote,
    pub model_quote: VerifiedTdxQuote,
    pub gateway_compose_hash: String,
    pub model_compose_hash: String,
}
const MAX_SESSION_FUTURE_SKEW_MS: u64 = 30_000;

pub fn verify_redpill_aci_capture(
    capture: &RedpillAciLiveEvidence,
    gateway_verifier: &dyn TinfoilQuoteVerifier,
    model_verifier: &dyn TinfoilQuoteVerifier,
    gpu_verifier: &dyn GpuAttestationVerifier,
    api_endpoint: &str,
    provider_model: &str,
    now_epoch_ms: u64,
) -> Result<VerifiedRedpillAciCapture> {
    if capture.schema != RedpillAciLiveEvidence::SCHEMA
        || capture.request_nonce.len() != 64
        || !capture
            .request_nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid schema or request nonce"));
    }
    let model = session_evidence(capture)?;
    // The session claims name the model the user asked for; bind it to the route.
    if field(&capture.session, "/claims/extra/canonical_model_id")? != provider_model {
        return Err(invalid("session claims canonical model mismatch"));
    }
    let (gateway_bytes, model_bytes) = redpill_aci_quote_bytes(capture)?;
    let gateway = gateway_verifier.verify_tdx_quote(&gateway_bytes)?;
    let model_quote = model_verifier.verify_tdx_quote(&model_bytes)?;
    let report = &capture.gateway_report;
    let (gateway_identity, gateway_compose_hash) = dstack_identity(
        field(report, "/attestation/evidence/event_log")?,
        &gateway.rtmr3,
    )?;
    let (model_identity, model_compose_hash) =
        dstack_identity(field(&model, "/event_log")?, &model_quote.rtmr3)?;
    // The replayed compose-hash must be the sha256 of the presented app_compose
    // document, so the app definition cannot be swapped behind a pinned hash.
    let tcb_info = model
        .pointer("/info/tcb_info")
        .ok_or_else(|| invalid("missing tcb info"))?;
    let tcb_info = match tcb_info {
        Value::String(encoded) => serde_json::from_str::<Value>(encoded)?,
        value => value.clone(),
    };
    if sha256_digest(field(&tcb_info, "/app_compose")?.as_bytes())
        != format!("sha256:{model_compose_hash}")
        || sha256_digest(field(report, "/attestation/evidence/app_compose")?.as_bytes())
            != format!("sha256:{gateway_compose_hash}")
    {
        return Err(invalid("app compose does not match replayed compose-hash"));
    }
    if field(report, "/api_version")? != "aci/1" || field(report, "/attestation/tee_type")? != "tdx"
    {
        return Err(invalid("unsupported gateway attestation"));
    }
    let keyset = report
        .pointer("/attestation/workload_keyset")
        .ok_or_else(|| invalid("missing keyset"))?;
    let digest = redpill_aci_jcs_digest(keyset)?;
    if digest != field(report, "/workload_keyset_digest")? {
        return Err(invalid("keyset digest mismatch"));
    }
    let statement = format!(
        "{{\"keyset_digest\":\"{digest}\",\"nonce\":\"{}\",\"purpose\":\"aci.report_data.v1\"}}",
        capture.request_nonce
    );
    let statement_hash = sha256_digest(statement.as_bytes());
    let expected_gateway_data = format!("{}{}", &statement_hash[7..], "00".repeat(32));
    if gateway.report_data != expected_gateway_data
        || field(report, "/attestation/report_data")? != &statement_hash[7..]
    {
        return Err(invalid("gateway quote does not bind fresh keyset"));
    }
    let cert = STANDARD
        .decode(&capture.live_tls_leaf_certificate_der_base64)
        .map_err(|_| invalid("invalid gateway certificate"))?;
    let spki = certificate_spki_sha256_hex(&cert)?;
    if spki != capture.live_tls_spki_sha256 {
        return Err(invalid("gateway certificate SPKI mismatch"));
    }
    let host = api_endpoint
        .strip_prefix("https://")
        .and_then(|s| s.split('/').next())
        .ok_or_else(|| invalid("API endpoint is not HTTPS"))?;
    let host = host
        .split(':')
        .next()
        .ok_or_else(|| invalid("missing API hostname"))?;
    let keys = keyset
        .get("tls_public_keys")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing TLS keyset"))?;
    if !keys.iter().any(|key| {
        key.get("spki_sha256").and_then(Value::as_str) == Some(spki.as_str())
            && key
                .get("domain")
                .is_none_or(|v| v.as_str().is_some_and(|d| d.eq_ignore_ascii_case(host)))
    }) {
        return Err(invalid("gateway SPKI not in hostname-scoped keyset"));
    }
    let keyset_expiry = keyset
        .get("not_after")
        .and_then(Value::as_u64)
        .and_then(|s| s.checked_mul(1000))
        .ok_or_else(|| invalid("invalid keyset expiry"))?;
    let established = capture
        .session
        .get("established_at")
        .and_then(Value::as_u64)
        .and_then(|s| s.checked_mul(1000))
        .ok_or_else(|| invalid("invalid session establishment"))?;
    let session_expiry = capture
        .session
        .get("expires_at")
        .and_then(Value::as_u64)
        .and_then(|s| s.checked_mul(1000))
        .ok_or_else(|| invalid("invalid session expiry"))?;
    if established > now_epoch_ms.saturating_add(MAX_SESSION_FUTURE_SKEW_MS)
        || session_expiry <= now_epoch_ms
        || established >= session_expiry
        || keyset_expiry <= now_epoch_ms
    {
        return Err(invalid("expired or future session/keyset"));
    }
    let (cert_start, cert_end) = certificate_validity_epoch_millis(&cert)?;
    if now_epoch_ms < cert_start || now_epoch_ms >= cert_end {
        return Err(invalid("gateway certificate is not valid"));
    }
    let nonce = field(&model, "/request_nonce")?;
    let nonce_bytes = hex(nonce)?;
    let address = field(&model, "/signing_address")?;
    let address_bytes = hex(address.strip_prefix("0x").unwrap_or(address))?;
    let upstream_spki = field(&model, "/tls_cert_fingerprint")?;
    let spki_bytes = hex(upstream_spki)?;
    if nonce_bytes.len() != 32 || address_bytes.len() != 20 || spki_bytes.len() != 32 {
        return Err(invalid("invalid model binding fields"));
    }
    let mut input = address_bytes;
    input.extend_from_slice(&spki_bytes);
    let mut expected = Sha256::digest(&input).to_vec();
    expected.extend_from_slice(&nonce_bytes);
    if hex(&model_quote.report_data)? != expected {
        return Err(invalid("model quote binding mismatch"));
    }
    let bindings = capture
        .session
        .get("channel_binding")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing session channel bindings"))?;
    let endpoint = field(&capture.session, "/endpoint")?;
    if !bindings.iter().any(|b| {
        b.get("type").and_then(Value::as_str) == Some("tls_spki_sha256")
            && b.get("spki_sha256").and_then(Value::as_str) == Some(upstream_spki)
            && b.get("origin").and_then(Value::as_str) == Some(endpoint)
    }) {
        return Err(invalid("session channel binding mismatch"));
    }
    let gpu = capture
        .gpu_attestation
        .as_ref()
        .ok_or_else(|| invalid("missing GPU attestation"))?;
    let payload = field(&model, "/nvidia_payload")?.as_bytes();
    if gpu.schema != NvidiaGpuAttestationEvidence::SCHEMA
        || gpu.attestation_format != NvidiaGpuAttestationEvidence::NRAS_GPU_EVIDENCE_V3
        || gpu.nonce != nonce
        || gpu.payload_sha256.as_deref() != Some(sha256_digest(payload).as_str())
        || gpu
            .raw_payload_base64
            .as_ref()
            .and_then(|s| STANDARD.decode(s).ok())
            .as_deref()
            != Some(payload)
    {
        return Err(invalid("GPU evidence does not match session"));
    }
    let verified_gpu =
        gpu_verifier.verify_nvidia_gpu_attestation(&NvidiaGpuAttestationVerificationRequest {
            evidence: gpu,
            expected_nonce: nonce,
            expected_tee: GpuTeeKind::NvidiaCc,
            provider: &capture.provider,
            route_id: &capture.route_id,
        })?;
    if verified_gpu.tee != GpuTeeKind::NvidiaCc
        || verified_gpu.nonce != nonce
        || verified_gpu.attestation_format != gpu.attestation_format
    {
        return Err(invalid("inconsistent GPU verification"));
    }
    let expires_at_epoch_ms = keyset_expiry
        .min(session_expiry)
        .min(cert_end)
        .min(gateway.expires_at_epoch_ms)
        .min(model_quote.expires_at_epoch_ms);
    if expires_at_epoch_ms <= now_epoch_ms {
        return Err(invalid("quote expired"));
    }
    let issued_at = if parse_utc_timestamp_millis(&gateway.issued_at)?
        >= parse_utc_timestamp_millis(&model_quote.issued_at)?
    {
        gateway.issued_at.clone()
    } else {
        model_quote.issued_at.clone()
    };
    Ok(VerifiedRedpillAciCapture {
        tee_measurement: format!(
            "{}:gateway_{gateway_identity}:upstream_{model_identity}",
            redpill_aci_tee_measurement(provider_model, &gateway, &model_quote)
        ),
        gateway_compose_hash,
        model_compose_hash,
        live_tls_spki_sha256: spki,
        issued_at,
        expires_at_epoch_ms,
        gateway_quote: gateway,
        model_quote,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TinfoilQuoteVerificationRequest, VerifiedGpuAttestation, VerifiedTinfoilQuote};

    struct Quote(bool);
    impl TinfoilQuoteVerifier for Quote {
        fn verify_tinfoil_quote(
            &self,
            _: &TinfoilQuoteVerificationRequest<'_>,
        ) -> Result<VerifiedTinfoilQuote> {
            Err(invalid("not a Tinfoil quote"))
        }
        fn verify_tdx_quote(&self, bytes: &[u8]) -> Result<VerifiedTdxQuote> {
            let mut data = bytes[568..632]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if self.0 {
                data.replace_range(0..2, "ff");
            }
            Ok(VerifiedTdxQuote {
                tee_measurement: "test".into(),
                mr_td: "td".into(),
                mr_config_id: "config".into(),
                rtmr0: "0".into(),
                rtmr1: "1".into(),
                rtmr2: "2".into(),
                rtmr3: bytes[520..568].iter().map(|b| format!("{b:02x}")).collect(),
                report_data: data,
                issued_at: "2026-11-02T00:00:00.000Z".into(),
                expires_at: "2030-01-01T00:00:00.000Z".into(),
                expires_at_epoch_ms: 1_893_456_000_000,
            })
        }
    }
    struct Gpu;
    impl GpuAttestationVerifier for Gpu {
        fn verify_nvidia_gpu_attestation(
            &self,
            request: &NvidiaGpuAttestationVerificationRequest<'_>,
        ) -> Result<VerifiedGpuAttestation> {
            Ok(VerifiedGpuAttestation::nvidia_cc(
                request.expected_nonce,
                request.evidence.attestation_format.clone(),
                "test",
            ))
        }
    }
    fn fixture() -> RedpillAciLiveEvidence {
        serde_json::from_str(include_str!("redpill_fixture.json")).unwrap()
    }
    const CLAIMED_MODEL: &str = "phala/gemma-4-26b-a4b-uncensored";
    const NOW_MS: u64 = 1_793_601_000_000;
    fn check(
        capture: &RedpillAciLiveEvidence,
        gateway: bool,
        model: bool,
    ) -> Result<VerifiedRedpillAciCapture> {
        verify_redpill_aci_capture(
            capture,
            &Quote(gateway),
            &Quote(model),
            &Gpu,
            "https://tee.redpill.ai/v1",
            CLAIMED_MODEL,
            NOW_MS,
        )
    }
    fn check_as(
        capture: &RedpillAciLiveEvidence,
        provider_model: &str,
    ) -> Result<VerifiedRedpillAciCapture> {
        verify_redpill_aci_capture(
            capture,
            &Quote(false),
            &Quote(false),
            &Gpu,
            "https://tee.redpill.ai/v1",
            provider_model,
            NOW_MS,
        )
    }
    fn replay_rtmr3(events: &[Value]) -> String {
        let mut acc = [0u8; 48];
        for event in events.iter().filter(|e| e["imr"] == 3) {
            let typ = (event["event_type"].as_u64().unwrap() as u32).to_le_bytes();
            let payload = hex(event["event_payload"].as_str().unwrap()).unwrap();
            let mut h = Sha384::new();
            h.update(typ);
            h.update(b":");
            h.update(event["event"].as_str().unwrap().as_bytes());
            h.update(b":");
            h.update(payload);
            let digest = h.finalize();
            let mut h = Sha384::new();
            h.update(acc);
            h.update(digest);
            acc.copy_from_slice(&h.finalize());
        }
        acc.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }
    fn gateway_capture_with_log(
        capture: &RedpillAciLiveEvidence,
        log: &str,
        rtmr3: &str,
    ) -> RedpillAciLiveEvidence {
        let mut changed = capture.clone();
        changed.gateway_report["attestation"]["evidence"]["event_log"] = log.into();
        let mut quote = changed.gateway_report["attestation"]["evidence"]["quote"]
            .as_str()
            .unwrap()
            .to_owned();
        quote.replace_range(1040..1136, rtmr3);
        changed.gateway_report["attestation"]["evidence"]["quote"] = quote.into();
        changed
    }
    fn model_evidence(capture: &RedpillAciLiveEvidence) -> Value {
        let encoded = field(&capture.session, "/evidence/data")
            .unwrap()
            .split_once(',')
            .unwrap()
            .1;
        serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap()
    }
    fn model_capture_with_evidence(
        capture: &RedpillAciLiveEvidence,
        mutate: impl FnOnce(&mut Value),
    ) -> RedpillAciLiveEvidence {
        let mut changed = capture.clone();
        let mut evidence = model_evidence(capture);
        mutate(&mut evidence);
        let bytes = serde_json::to_vec(&evidence).unwrap();
        changed.session["evidence"]["data"] =
            format!("data:application/json;base64,{}", STANDARD.encode(&bytes)).into();
        changed.session["evidence"]["digest"] = sha256_digest(&bytes).into();
        changed.session_id = redpill_aci_jcs_digest(&changed.session).unwrap()[7..].to_owned();
        changed
    }
    #[test]
    fn captured_gateway_and_model_bindings_fail_closed() {
        let capture = fixture();
        assert!(check(&capture, false, false).is_ok());
        assert!(check(&capture, true, false).is_err());
        assert!(check(&capture, false, true).is_err());
        let mut altered = capture.clone();
        altered.request_nonce = "01".repeat(32);
        assert!(check(&altered, false, false).is_err());
        let mut altered = capture.clone();
        altered.live_tls_spki_sha256 = "00".repeat(32);
        assert!(check(&altered, false, false).is_err());
        let mut altered = capture.clone();
        altered.session_id = "00".repeat(32);
        assert!(check(&altered, false, false).is_err());
        let mut altered = capture;
        altered.session["evidence"]["digest"] = "sha256:bad".into();
        altered.session_id = redpill_aci_jcs_digest(&altered.session).unwrap()[7..].to_owned();
        assert!(check(&altered, false, false).is_err());
    }

    #[test]
    fn rehashed_session_cannot_replace_model_quote_or_gpu_bindings() {
        let capture = fixture();
        let altered = model_capture_with_evidence(&capture, |e| {
            e["signing_address"] = format!("0x{}", "00".repeat(20)).into();
        });
        assert!(check(&altered, false, false).is_err());
        let altered = model_capture_with_evidence(&capture, |e| {
            e["tls_cert_fingerprint"] = "00".repeat(32).into();
        });
        assert!(check(&altered, false, false).is_err());
        let altered = model_capture_with_evidence(&capture, |e| {
            e["nvidia_payload"] = "{}".into();
        });
        assert!(check(&altered, false, false).is_err());
        let mut altered = capture;
        altered.session["channel_binding"][0]["spki_sha256"] = "00".repeat(32).into();
        altered.session_id = redpill_aci_jcs_digest(&altered.session).unwrap()[7..].to_owned();
        assert!(check(&altered, false, false).is_err());
    }

    #[test]
    fn measurement_pin_changes_for_either_tee_or_model() {
        let verified = check(&fixture(), false, false).unwrap();
        let mut gateway = verified.gateway_quote.clone();
        let mut model = verified.model_quote.clone();
        let pinned = [redpill_aci_tee_measurement("test", &gateway, &model)];
        gateway.mr_td = "untrusted".into();
        assert!(!pinned.contains(&redpill_aci_tee_measurement("test", &gateway, &model)));
        gateway = verified.gateway_quote;
        model.mr_td = "untrusted".into();
        assert!(!pinned.contains(&redpill_aci_tee_measurement("test", &gateway, &model)));
        assert!(!pinned.contains(&redpill_aci_tee_measurement("other", &gateway, &model)));
        model = verified.model_quote;
        gateway.rtmr3 = "different-instance".into();
        model.rtmr3 = "different-instance".into();
        assert!(pinned.contains(&redpill_aci_tee_measurement("test", &gateway, &model)));
    }

    #[test]
    fn dstack_log_replay_pins_compose_and_ignores_instance_changes() {
        let capture = fixture();
        let log = field(&capture.gateway_report, "/attestation/evidence/event_log").unwrap();
        let quoted = Quote(false)
            .verify_tdx_quote(&redpill_aci_quote_bytes(&capture).unwrap().0)
            .unwrap();
        let identity = dstack_identity(log, &quoted.rtmr3).unwrap().0;
        let mut events: Vec<Value> = serde_json::from_str(log).unwrap();
        let instance = events
            .iter_mut()
            .find(|e| e["event"] == "instance-id")
            .unwrap();
        instance["event_payload"] = "11".repeat(20).into();
        instance["digest"] = "".into();
        let changed_rtmr3 = replay_rtmr3(&events);
        let changed_log = serde_json::to_string(&events).unwrap();
        assert_ne!(changed_rtmr3, quoted.rtmr3);
        assert_eq!(
            dstack_identity(&changed_log, &changed_rtmr3).unwrap().0,
            identity
        );
        assert!(dstack_identity(&changed_log, &quoted.rtmr3).is_err());
        let pinned = check(&capture, false, false).unwrap().tee_measurement;
        assert_eq!(
            check(
                &gateway_capture_with_log(&capture, &changed_log, &changed_rtmr3),
                false,
                false
            )
            .unwrap()
            .tee_measurement,
            pinned
        );
        let compose = events
            .iter_mut()
            .find(|e| e["event"] == "compose-hash")
            .unwrap();
        compose["event_payload"] = "22".repeat(32).into();
        compose["digest"] = "".into();
        let changed_rtmr3 = replay_rtmr3(&events);
        let changed_log = serde_json::to_string(&events).unwrap();
        let (changed_identity, changed_compose) =
            dstack_identity(&changed_log, &changed_rtmr3).unwrap();
        assert_ne!(changed_identity, identity);
        assert_eq!(changed_compose, "22".repeat(32));
        // The presented app_compose no longer matches the replayed compose-hash.
        assert!(check(
            &gateway_capture_with_log(&capture, &changed_log, &changed_rtmr3),
            false,
            false
        )
        .is_err());
    }

    #[test]
    fn session_claims_model_must_match_route_provider_model() {
        let capture = fixture();
        assert!(check_as(&capture, CLAIMED_MODEL).is_ok());
        for wrong in [
            "test",
            "phala/other-model",
            "",
            "phala/GEMMA-4-26B-A4B-UNCENSORED",
        ] {
            assert!(check_as(&capture, wrong).is_err());
        }
        let mut altered = capture.clone();
        altered.session["claims"]["extra"]["canonical_model_id"] = "phala/other-model".into();
        altered.session_id = redpill_aci_jcs_digest(&altered.session).unwrap()[7..].to_owned();
        assert!(check(&altered, false, false).is_err());
        let mut altered = capture;
        altered.session["claims"]["extra"]
            .as_object_mut()
            .unwrap()
            .remove("canonical_model_id");
        altered.session_id = redpill_aci_jcs_digest(&altered.session).unwrap()[7..].to_owned();
        assert!(check(&altered, false, false).is_err());
    }

    #[test]
    fn session_established_at_allows_only_30s_future_skew() {
        let capture = fixture();
        let expires = capture.session["expires_at"].as_u64().unwrap();
        let set_established = |seconds: u64| {
            let mut altered = capture.clone();
            altered.session["established_at"] = seconds.into();
            altered.session_id = redpill_aci_jcs_digest(&altered.session).unwrap()[7..].to_owned();
            altered
        };
        assert!(check(&set_established(NOW_MS / 1000 + 30), false, false).is_ok());
        assert!(check(&set_established(NOW_MS / 1000 + 31), false, false).is_err());
        assert!(check(&set_established(expires + 1), false, false).is_err());
    }

    #[test]
    fn replayed_compose_hashes_are_exposed_bare_hex() {
        let capture = fixture();
        let verified = check(&capture, false, false).unwrap();
        assert_eq!(
            verified.gateway_compose_hash,
            "aa767dbc886174737fcc77083851e3dbdea093b976404755a3f5a68c0d9e7992"
        );
        assert_eq!(
            verified.model_compose_hash,
            "d7690f7d6b11f781b75e1d7ceb99a87a6f6cc9f2e15750ecb6fdd35baf5bff98"
        );
        // The measured identity pins the replayed KMS root and key provider.
        assert!(verified
            .tee_measurement
            .contains(":kms:74ff129578a39692eb359d6caaf3ddb940902c030af812d05e4d391f832c71a2"));
        let log = field(&capture.gateway_report, "/attestation/evidence/event_log").unwrap();
        let key_provider = serde_json::from_str::<Vec<Value>>(log)
            .unwrap()
            .iter()
            .find(|e| e["event"] == "key-provider")
            .unwrap()["event_payload"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(verified
            .tee_measurement
            .contains(&format!(":key_provider:{key_provider}")));
    }

    #[test]
    fn app_compose_documents_must_hash_to_replayed_compose() {
        let capture = fixture();
        let mut altered = capture.clone();
        altered.gateway_report["attestation"]["evidence"]["app_compose"] = "{}".into();
        assert!(check(&altered, false, false).is_err());
        let mut altered = capture.clone();
        altered.gateway_report["attestation"]["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("app_compose");
        assert!(check(&altered, false, false).is_err());
        let altered = model_capture_with_evidence(&capture, |e| {
            e["info"]["tcb_info"]["app_compose"] = "{}".into()
        });
        assert!(check(&altered, false, false).is_err());
        // tcb_info may arrive as a JSON-encoded string; the binding still holds.
        let altered = model_capture_with_evidence(&capture, |e| {
            e["info"]["tcb_info"] = serde_json::to_string(&e["info"]["tcb_info"])
                .unwrap()
                .into()
        });
        assert!(check(&altered, false, false).is_ok());
        let altered = model_capture_with_evidence(&capture, |e| {
            e["info"].as_object_mut().unwrap().remove("tcb_info");
        });
        assert!(check(&altered, false, false).is_err());
    }

    #[test]
    fn kms_and_key_provider_events_pin_identity() {
        let capture = fixture();
        let log = field(&capture.gateway_report, "/attestation/evidence/event_log").unwrap();
        let quoted = Quote(false)
            .verify_tdx_quote(&redpill_aci_quote_bytes(&capture).unwrap().0)
            .unwrap();
        let identity = dstack_identity(log, &quoted.rtmr3).unwrap().0;
        let pinned = check(&capture, false, false).unwrap().tee_measurement;
        let events: Vec<Value> = serde_json::from_str(log).unwrap();
        let to_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let patch = |name: &str, payload: String| {
            let mut changed = events.clone();
            let event = changed.iter_mut().find(|e| e["event"] == name).unwrap();
            event["event_payload"] = payload.into();
            event["digest"] = "".into();
            let rtmr3 = replay_rtmr3(&changed);
            let log = serde_json::to_string(&changed).unwrap();
            let verified = check(
                &gateway_capture_with_log(&capture, &log, &rtmr3),
                false,
                false,
            )
            .unwrap();
            assert_ne!(dstack_identity(&log, &rtmr3).unwrap().0, identity);
            assert_ne!(verified.tee_measurement, pinned);
        };
        // Altered mr-kms and key-provider payloads must change the pinned identity.
        patch("mr-kms", "33".repeat(32));
        let kp = events
            .iter()
            .find(|e| e["event"] == "key-provider")
            .unwrap()["event_payload"]
            .as_str()
            .unwrap();
        let mut kp_json: Value = serde_json::from_slice(&hex(kp).unwrap()).unwrap();
        kp_json["name"] = "rogue-kms".into();
        patch(
            "key-provider",
            to_hex(serde_json::to_string(&kp_json).unwrap().as_bytes()),
        );
        // Duplicate and missing identity events are rejected.
        for name in ["compose-hash", "mr-kms", "key-provider"] {
            let mut dup = events.clone();
            let event = dup.iter().find(|e| e["event"] == name).unwrap().clone();
            dup.push(event);
            let rtmr3 = replay_rtmr3(&dup);
            assert!(dstack_identity(&serde_json::to_string(&dup).unwrap(), &rtmr3).is_err());
        }
        for name in ["mr-kms", "key-provider"] {
            let mut missing: Vec<Value> = events
                .iter()
                .filter(|e| e["event"] != name)
                .cloned()
                .collect();
            missing.iter_mut().for_each(|e| {
                e["digest"] = "".into();
            });
            let rtmr3 = replay_rtmr3(&missing);
            let log = serde_json::to_string(&missing).unwrap();
            assert!(dstack_identity(&log, &rtmr3).is_err());
            assert!(check(
                &gateway_capture_with_log(&capture, &log, &rtmr3),
                false,
                false
            )
            .is_err());
        }
        // A duplicate in the captured gateway log must fail verification.
        let mut dup = events.clone();
        let event = dup
            .iter()
            .find(|e| e["event"] == "compose-hash")
            .unwrap()
            .clone();
        dup.push(event);
        assert!(check(
            &gateway_capture_with_log(
                &capture,
                &serde_json::to_string(&dup).unwrap(),
                &replay_rtmr3(&dup)
            ),
            false,
            false
        )
        .is_err());
        // The model-side log applies the same pinning.
        let model_log = field(&model_evidence(&capture), "/event_log")
            .unwrap()
            .to_owned();
        let mut model_events: Vec<Value> = serde_json::from_str(&model_log).unwrap();
        let mr = model_events
            .iter_mut()
            .find(|e| e["event"] == "mr-kms")
            .unwrap();
        mr["event_payload"] = "44".repeat(32).into();
        mr["digest"] = "".into();
        let rtmr3 = replay_rtmr3(&model_events);
        let altered = model_capture_with_evidence(&capture, |e| {
            e["event_log"] = serde_json::to_string(&model_events).unwrap().into();
            let mut quote = e["intel_quote"].as_str().unwrap().to_owned();
            quote.replace_range(1040..1136, &rtmr3);
            e["intel_quote"] = quote.into();
        });
        assert_ne!(
            check(&altered, false, false).unwrap().tee_measurement,
            pinned
        );
        let mut model_events: Vec<Value> = serde_json::from_str(&model_log).unwrap();
        model_events.retain(|e| e["event"] != "key-provider");
        let rtmr3 = replay_rtmr3(&model_events);
        let altered = model_capture_with_evidence(&capture, |e| {
            e["event_log"] = serde_json::to_string(&model_events).unwrap().into();
            let mut quote = e["intel_quote"].as_str().unwrap().to_owned();
            quote.replace_range(1040..1136, &rtmr3);
            e["intel_quote"] = quote.into();
        });
        assert!(check(&altered, false, false).is_err());
    }

    #[test]
    fn jcs_handles_ecmascript_numbers_and_utf16_order() {
        let value: Value =
            serde_json::from_str(r#"{"\ue000":1,"\ud800\udc00":2,"n":1e-7}"#).unwrap();
        assert_eq!(
            serde_json_canonicalizer::to_string(&value).unwrap(),
            "{\"n\":1e-7,\"𐀀\":2,\"\":1}"
        );
    }
}
