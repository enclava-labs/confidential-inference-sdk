#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    confidential_inference_providers::fuzzing::sse_frames(data);
});
