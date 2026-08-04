#ifndef CONFIDENTIAL_INFERENCE_FFI_H
#define CONFIDENTIAL_INFERENCE_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONFIDENTIAL_INFERENCE_FFI_OK 0
#define CONFIDENTIAL_INFERENCE_FFI_INVALID_ARGUMENT 1
#define CONFIDENTIAL_INFERENCE_FFI_PANIC 2
#define CONFIDENTIAL_INFERENCE_FFI_BUSY 3
#define CONFIDENTIAL_INFERENCE_FFI_PENDING 4
#define CONFIDENTIAL_INFERENCE_FFI_UNSUPPORTED 5
#define CONFIDENTIAL_INFERENCE_FFI_INTERNAL 6

typedef struct ConfidentialInferenceFfiClient ConfidentialInferenceFfiClient;
typedef struct ConfidentialInferenceFfiStream ConfidentialInferenceFfiStream;

int confidential_inference_status(char **out_status_json);

int confidential_inference_sdk_new(const char *config_json, ConfidentialInferenceFfiClient **out_client);
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
