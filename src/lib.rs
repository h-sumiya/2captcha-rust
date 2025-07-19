//! # TwoCaptcha Rust Library
//!
//! A Rust library for easy integration with the 2captcha captcha solving service.
//! This library allows you to solve various types of captchas including reCAPTCHA,
//! FunCaptcha, GeeTest, hCaptcha, and many others.
//!
//! ## Example
//!
//! ```no_run
//! use twocaptcha::{TwoCaptcha, TwoCaptchaConfig, RecaptchaVersion};
//! use std::collections::HashMap;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let solver = TwoCaptcha::new("your_api_key".to_string(), TwoCaptchaConfig::default());
//!
//!     // Solve a reCAPTCHA
//!     let result = solver.recaptcha(
//!         "site_key",
//!         "https://example.com",
//!         Some(RecaptchaVersion::V2),
//!         Some(false), // enterprise
//!         None, // additional params
//!     ).await?;
//!
//!     println!("Captcha solved: {}", result.code.unwrap_or_default());
//!     Ok(())
//! }
//! ```

pub mod api;
pub mod error;
pub mod solver;
pub mod types;
pub mod utils;

// Re-export main types
pub use api::ApiClient;
pub use error::{Result, TwoCaptchaError};
pub use solver::{TwoCaptcha, TwoCaptchaConfig};
pub use types::{AudioLanguage, Balance, CaptchaResult, ExtendedResponse, Proxy, RecaptchaVersion};

// Re-export commonly used traits
pub use error::SolverExceptions;
