#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    confidential_inference_attestation::fuzzing::sev_snp_report(data);
});
