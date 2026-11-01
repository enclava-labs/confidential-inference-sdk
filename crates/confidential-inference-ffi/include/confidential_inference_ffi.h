#ifndef CONFIDENTIAL_INFERENCE_FFI_H
#define CONFIDENTIAL_INFERENCE_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONFIDENTIAL_INFERENCE_FFI_ABI_VERSION 1
#define CONFIDENTIAL_INFERENCE_FFI_OK 0
#define CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT 1
#define CONFIDENTIAL_INFERENCE_FFI_PANIC 2
#define CONFIDENTIAL_INFERENCE_FFI_BUSY 3
#define CONFIDENTIAL_INFERENCE_FFI_PENDING 4
#define CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED 5
#define CONFIDENTIAL_INFERENCE_FFI_INTERNAL 6
/* An SDK operation failed. The error envelope carries "code", "message",
 * "dispatch" ("not_dispatched" | "rejected" | "unknown": whether the provider
 * may have processed the request) and, for "rejected", "http_status". */
#define CONFIDENTIAL_INFERENCE_FFI_OPERATION_FAILED 7

typedef struct ConfidentialInferenceFfiClient ConfidentialInferenceFfiClient;
typedef struct ConfidentialInferenceFfiStream ConfidentialInferenceFfiStream;

/* JSON-output calls return their call-specific error envelope through the
 * output pointer on failure. Free it with confidential_inference_string_free. */

int confidential_inference_status(char **out_status_json);

int confidential_inference_sdk_new(const char *config_json, ConfidentialInferenceFfiClient **out_client);
/* sdk_free: CONFIDENTIAL_INFERENCE_FFI_BUSY only while live streams reference
 * the client (blocking calls are not counted — they hold Arc clones of the
 * shared state, so freeing stays memory-safe while they run). In a forked
 * child it releases the handle and leaks the runtime rather than dropping it;
 * create clients after fork. */
int confidential_inference_sdk_free(ConfidentialInferenceFfiClient *client);

int confidential_inference_chat_blocking(
    ConfidentialInferenceFfiClient *client,
    const char *request_json,
    uint64_t timeout_ms,
    char **out_response_json
);
int confidential_inference_response_blocking(
    ConfidentialInferenceFfiClient *client,
    const char *request_json,
    uint64_t timeout_ms,
    char **out_response_json
);
int confidential_inference_response_manage_blocking(
    ConfidentialInferenceFfiClient *client,
    const char *request_json,
    uint64_t timeout_ms,
    char **out_response_json
);
int confidential_inference_embeddings_blocking(
    ConfidentialInferenceFfiClient *client,
    const char *request_json,
    uint64_t timeout_ms,
    char **out_response_json
);

int confidential_inference_verify_blocking(
    ConfidentialInferenceFfiClient *client,
    const char *request_json,
    uint64_t timeout_ms,
    char **out_verdict_json
);
int confidential_inference_models_blocking(
    ConfidentialInferenceFfiClient *client,
    char **out_models_json
);
int confidential_inference_confidentiality_blocking(
    ConfidentialInferenceFfiClient *client,
    char **out_catalog_json
);
int confidential_inference_active_policy_blocking(
    ConfidentialInferenceFfiClient *client,
    char **out_policy_json
);
int confidential_inference_active_trust_artifacts_blocking(
    ConfidentialInferenceFfiClient *client,
    char **out_artifacts_json
);

int confidential_inference_chat_stream_start(
    ConfidentialInferenceFfiClient *client,
    const char *request_json,
    ConfidentialInferenceFfiStream **out_stream
);
/* stream_next: timeout_ms == 0 is a non-blocking poll returning
 * CONFIDENTIAL_INFERENCE_FFI_PENDING when no event is ready — unlike the
 * *_blocking exports, it never waits indefinitely. */
int confidential_inference_stream_next(
    ConfidentialInferenceFfiStream *stream,
    uint64_t timeout_ms,
    char **out_event_json
);
int confidential_inference_stream_cancel(ConfidentialInferenceFfiStream *stream);
int confidential_inference_stream_free(ConfidentialInferenceFfiStream *stream);

int confidential_inference_last_error(char **out_error_json);
void confidential_inference_string_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif
