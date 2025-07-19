use std::collections::HashMap;
use twocaptcha::{RecaptchaVersion, TwoCaptcha};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with your API key
    let api_key =
        std::env::var("TWOCAPTCHA_API_KEY").unwrap_or_else(|_| "YOUR_API_KEY".to_string());

    let solver = TwoCaptcha::new(
        api_key, None, // soft_id
        None, // callback
        None, // default_timeout
        None, // recaptcha_timeout
        None, // polling_interval
        None, // server
        None, // extended_response
    );

    println!("2captcha Rust Library Example");
    println!("==============================");

    // Check balance
    match solver.balance().await {
        Ok(balance) => println!("Account balance: ${:.2}", balance.0),
        Err(e) => println!("Failed to get balance: {}", e),
    }

    // Example 1: Normal captcha (uncomment to test with actual image)
    /*
    println!("\n1. Solving normal captcha...");
    match solver.normal("path/to/captcha.jpg", None).await {
        Ok(result) => println!("Normal captcha solved: {}", result.code.unwrap_or_default()),
        Err(e) => println!("Failed to solve normal captcha: {}", e),
    }
    */

    // Example 2: Text captcha
    println!("\n2. Solving text captcha...");
    match solver.text("What is 2+2?", None).await {
        Ok(result) => println!("Text captcha result: {}", result.code.unwrap_or_default()),
        Err(e) => println!("Failed to solve text captcha: {}", e),
    }

    // Example 3: reCAPTCHA v2 (demo site)
    println!("\n3. Solving reCAPTCHA v2...");
    match solver
        .recaptcha(
            "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-",
            "https://www.google.com/recaptcha/api2/demo",
            Some(RecaptchaVersion::V2),
            Some(false),
            None,
        )
        .await
    {
        Ok(result) => println!("reCAPTCHA v2 solved: {}", result.code.unwrap_or_default()),
        Err(e) => println!("Failed to solve reCAPTCHA v2: {}", e),
    }

    // Example 4: reCAPTCHA v3 with custom parameters
    println!("\n4. Solving reCAPTCHA v3...");
    let mut params = HashMap::new();
    params.insert("min_score".to_string(), "0.3".to_string());
    params.insert("action".to_string(), "verify".to_string());

    match solver
        .recaptcha(
            "6LfB5_IbAAAAAMCtsjEHEHKqcB9iQocwwxTiihJu",
            "https://2captcha.com/demo/recaptcha-v3",
            Some(RecaptchaVersion::V3),
            Some(false),
            Some(params),
        )
        .await
    {
        Ok(result) => println!("reCAPTCHA v3 solved: {}", result.code.unwrap_or_default()),
        Err(e) => println!("Failed to solve reCAPTCHA v3: {}", e),
    }

    // Example 5: hCaptcha
    println!("\n5. Solving hCaptcha...");
    match solver
        .hcaptcha(
            "4c672d35-0701-42b2-88c3-78380b0db560",
            "https://accounts.hcaptcha.com/demo",
            None,
        )
        .await
    {
        Ok(result) => println!("hCaptcha solved: {}", result.code.unwrap_or_default()),
        Err(e) => println!("Failed to solve hCaptcha: {}", e),
    }

    // Example 6: FunCaptcha
    println!("\n6. Solving FunCaptcha...");
    match solver
        .funcaptcha(
            "69A21A01-CC7B-B9C6-0F9A-E7FA06677FFC",
            "https://client-demo.arkoselabs.com/solo-animals",
            None,
        )
        .await
    {
        Ok(result) => println!("FunCaptcha solved: {}", result.code.unwrap_or_default()),
        Err(e) => println!("Failed to solve FunCaptcha: {}", e),
    }

    println!("\nExample completed!");
    Ok(())
}
