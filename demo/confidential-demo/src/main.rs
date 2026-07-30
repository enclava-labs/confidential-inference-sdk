// Minimal offline confidential-inference smoke example.
// Runs the bundled demo provider end-to-end with no network access.
// Behavior coverage lives in `cargo test --workspace`.
use confidential_inference_openai::ChatMessage;
use confidential_inference_sdk::ConfidentialInference;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ConfidentialInference::builder()
        .with_demo_provider()
        .build()
        .await?;
    let response = client
        .chat_completions()
        .model("gpt-oss-120b")
        .message(ChatMessage::user("hello from the offline demo"))
        .send()
        .await?;
    println!(
        "demo provider={provider} model={model} verdict={verdict:?} content={content:?}",
        provider = response.provider,
        model = response.provider_model,
        verdict = response.verdict.status,
        content = response.response.choices[0].message.content,
    );
    Ok(())
}
