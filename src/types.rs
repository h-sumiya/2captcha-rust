use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub uri: String,
}

/// Extended response structure when json=1 is used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedResponse {
    pub status: i32,
    pub request: Option<String>,
    pub code: Option<String>,
    pub cookies: Option<HashMap<String, String>>,
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Standard captcha solution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaResult {
    #[serde(rename = "captchaId")]
    pub captcha_id: String,
    pub code: Option<String>,
    #[serde(flatten)]
    pub extended: Option<HashMap<String, serde_json::Value>>,
}

/// Balance response
#[derive(Debug, Clone)]
pub struct Balance(pub f64);

/// Audio captcha supported languages
#[derive(Debug, Clone)]
pub enum AudioLanguage {
    English,
    Russian,
    German,
    Greek,
    Portuguese,
    French,
}

impl AudioLanguage {
    pub fn as_str(&self) -> &'static str {
        match self {
            AudioLanguage::English => "en",
            AudioLanguage::Russian => "ru",
            AudioLanguage::German => "de",
            AudioLanguage::Greek => "el",
            AudioLanguage::Portuguese => "pt",
            AudioLanguage::French => "fr",
        }
    }
}

impl std::str::FromStr for AudioLanguage {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "en" => Ok(AudioLanguage::English),
            "ru" => Ok(AudioLanguage::Russian),
            "de" => Ok(AudioLanguage::German),
            "el" => Ok(AudioLanguage::Greek),
            "pt" => Ok(AudioLanguage::Portuguese),
            "fr" => Ok(AudioLanguage::French),
            _ => Err(()),
        }
    }
}

/// reCAPTCHA version
#[derive(Debug, Clone)]
pub enum RecaptchaVersion {
    V2,
    V3,
}

impl RecaptchaVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecaptchaVersion::V2 => "v2",
            RecaptchaVersion::V3 => "v3",
        }
    }
}
