use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct VendorAudit {
    schema: String,
    upstream_sync_policy: UpstreamSyncPolicy,
    audited_files: Vec<AuditedFile>,
    required_substrings: Vec<PatternRule>,
    forbidden_substrings: Vec<PatternRule>,
}

#[derive(Debug, Deserialize)]
struct UpstreamSyncPolicy {
    path: String,
    required_release_gate: bool,
    review_triggers: Vec<String>,
    required_commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AuditedFile {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct PatternRule {
    path: String,
    value: String,
}

#[test]
fn dcap_qvl_audit_manifest_matches_workspace() {
    let workspace = workspace_root();
    let audit_path = workspace.join("fixtures/supply-chain/dcap-qvl-audit.json");
    let audit_json = fs::read_to_string(&audit_path).unwrap_or_else(|error| {
        panic!(
            "failed to read audit manifest {}: {error}",
            audit_path.display()
        )
    });
    let audit: VendorAudit = serde_json::from_str(&audit_json).unwrap_or_else(|error| {
        panic!(
            "failed to parse audit manifest {}: {error}",
            audit_path.display()
        )
    });

    assert_eq!(audit.schema, "confidential-inference.dcap-qvl-audit.v1");
    assert!(!audit.audited_files.is_empty());
    assert_eq!(
        audit.upstream_sync_policy.path,
        "docs/dcap-qvl-upstream-sync.md"
    );
    assert!(audit.upstream_sync_policy.required_release_gate);
    assert!(!audit.upstream_sync_policy.review_triggers.is_empty());
    assert!(
        audit
            .audited_files
            .iter()
            .any(|audited| audited.path == audit.upstream_sync_policy.path),
        "upstream sync policy must be covered by audited file hashes"
    );
    let policy_text = read_workspace_text(&workspace, &audit.upstream_sync_policy.path);
    for command in [
        "cargo test -p confidential-inference-providers --test dcap_qvl_audit --locked",
        "cargo test -p confidential-inference-attestation dcap_tdx_malformed_corpus --locked",
        "cargo test -p confidential-inference-attestation dcap_tdx_mutation_sweep --locked",
        "cargo test --workspace --locked",
        "cargo deny check",
        "cargo audit --ignore RUSTSEC-2023-0071",
    ] {
        assert!(
            audit
                .upstream_sync_policy
                .required_commands
                .contains(&command.to_owned()),
            "upstream sync policy manifest is missing required command: {command}"
        );
        assert!(
            policy_text.contains(command),
            "upstream sync policy document is missing required command: {command}"
        );
    }
    assert!(
        policy_text.contains("human security review"),
        "upstream sync policy must require human security review before production readiness"
    );
    assert!(
        policy_text.contains("confidential-inference.dcap-qvl-production-review.v1")
            && policy_text.contains("--dcap-production-review"),
        "upstream sync policy must document the production review attestation release gate"
    );

    for audited in &audit.audited_files {
        let path = workspace.join(&audited.path);
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let actual = sha256_hex(&bytes);
        assert_eq!(
            actual, audited.sha256,
            "audited file drifted: {}",
            audited.path
        );
    }

    for rule in &audit.required_substrings {
        let text = read_workspace_text(&workspace, &rule.path);
        assert!(
            text.contains(&rule.value),
            "audited file {} is missing required text: {:?}",
            rule.path,
            rule.value
        );
    }

    for rule in &audit.forbidden_substrings {
        let text = read_workspace_text(&workspace, &rule.path);
        assert!(
            !text.contains(&rule.value),
            "audited file {} contains forbidden text: {:?}",
            rule.path,
            rule.value
        );
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should resolve")
}

fn read_workspace_text(workspace: &Path, relative_path: &str) -> String {
    let path = workspace.join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}
