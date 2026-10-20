use confidential_inference_openai::ChatMessage;
use confidential_inference_sdk::ConfidentialInference;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // with_demo_provider is the explicit opt-in that trusts the bundled
    // fixture signing keys for the bundled artifacts only. Production
    // clients instead configure exclusive_trusted_artifact_signing_keys
    // with operator-controlled keys and their own artifact sources.
    let client = ConfidentialInference::builder()
        .with_demo_provider()
        .build()
        .await?;

    let result = client
        .chat_completions()
        .model("gpt-oss-120b")
        .message(ChatMessage::user("Explain why this route is trusted."))
        .send()
        .await?;

    println!("status: {:?}", result.verdict.status);
    println!(
        "response: {}",
        result.response.choices[0]
            .message
            .content
            .text()
            .unwrap_or_default()
    );
    Ok(())
}
