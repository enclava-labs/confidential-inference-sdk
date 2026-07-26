use confidential_inference_openai::ChatMessage;
use confidential_inference_sdk::ConfidentialInference;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    println!("response: {}", result.response.choices[0].message.content);
    Ok(())
}
