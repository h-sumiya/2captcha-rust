use crate::error::{Result, TwoCaptchaError};
use base64::Engine;
use std::collections::HashMap;
use std::path::Path;

/// Utility functions for file handling and encoding
pub struct Utils;

impl Utils {
    /// Determine method for file input (base64 or file path)
    pub async fn get_method(file: &str) -> Result<HashMap<String, String>> {
        if file.is_empty() {
            return Err(TwoCaptchaError::Validation("File required".to_string()));
        }

        // Check if it's a base64 string (no dots and length > 50)
        if !file.contains('.') && file.len() > 50 {
            let mut result = HashMap::new();
            result.insert("method".to_string(), "base64".to_string());
            result.insert("body".to_string(), file.to_string());
            return Ok(result);
        }

        // Check if it's a URL
        if file.starts_with("http") {
            let response = reqwest::get(file).await?;
            if response.status() != 200 {
                return Err(TwoCaptchaError::Validation(format!(
                    "File could not be downloaded from url: {}",
                    file
                )));
            }
            let content = response.bytes().await?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&content);

            let mut result = HashMap::new();
            result.insert("method".to_string(), "base64".to_string());
            result.insert("body".to_string(), encoded);
            return Ok(result);
        }

        // Check if file exists
        if !Path::new(file).exists() {
            return Err(TwoCaptchaError::Validation(format!(
                "File not found: {}",
                file
            )));
        }

        let mut result = HashMap::new();
        result.insert("method".to_string(), "post".to_string());
        result.insert("file".to_string(), file.to_string());
        Ok(result)
    }

    /// Extract and validate multiple files
    pub fn extract_files(files: Vec<String>, max_files: usize) -> Result<HashMap<String, String>> {
        if files.len() > max_files {
            return Err(TwoCaptchaError::Validation(format!(
                "Too many files (max: {})",
                max_files
            )));
        }

        let not_exists: Vec<&String> = files.iter().filter(|f| !Path::new(f).exists()).collect();

        if !not_exists.is_empty() {
            return Err(TwoCaptchaError::Validation(format!(
                "File not found: {:?}",
                not_exists
            )));
        }

        let mut result = HashMap::new();
        for (i, file) in files.iter().enumerate() {
            result.insert(format!("file_{}", i + 1), file.clone());
        }

        Ok(result)
    }

    /// Check and process hint image
    pub async fn check_hint_img(
        mut params: HashMap<String, String>,
        mut files: HashMap<String, String>,
    ) -> Result<(HashMap<String, String>, HashMap<String, String>)> {
        if let Some(hint) = params.remove("imginstructions") {
            // Check if it's a base64 string
            if !hint.contains('.') && hint.len() > 50 {
                params.insert("imginstructions".to_string(), hint);
                return Ok((params, files));
            }

            // Check if file exists
            if !Path::new(&hint).exists() {
                return Err(TwoCaptchaError::Validation(format!(
                    "File not found: {}",
                    hint
                )));
            }

            // If files is empty, add the main file
            if files.is_empty() {
                if let Some(file) = params.remove("file") {
                    files.insert("file".to_string(), file);
                }
            }

            files.insert("imginstructions".to_string(), hint);
        }

        Ok((params, files))
    }

    /// Rename parameters to match 2captcha API expectations
    pub fn rename_params(mut params: HashMap<String, String>) -> HashMap<String, String> {
        let replacements = [
            ("caseSensitive", "regsense"),
            ("minLen", "min_len"),
            ("maxLen", "max_len"),
            ("minLength", "min_len"),
            ("maxLength", "max_len"),
            ("hintText", "textinstructions"),
            ("hintImg", "imginstructions"),
            ("url", "pageurl"),
            ("score", "min_score"),
            ("text", "textcaptcha"),
            ("rows", "recaptcharows"),
            ("cols", "recaptchacols"),
            ("previousId", "previousID"),
            ("canSkip", "can_no_answer"),
            ("apiServer", "api_server"),
            ("softId", "soft_id"),
            ("callback", "pingback"),
            ("datas", "data-s"),
        ];

        let mut new_params = HashMap::new();

        // Apply replacements
        for (old_key, new_key) in &replacements {
            if let Some(value) = params.remove(*old_key) {
                new_params.insert(new_key.to_string(), value);
            }
        }

        // Handle proxy separately
        if let Some(proxy_str) = params.remove("proxy") {
            // Parse proxy format: {"type": "HTTPS", "uri": "login:password@IP_address:PORT"}
            if let Ok(proxy_data) = serde_json::from_str::<serde_json::Value>(&proxy_str) {
                if let (Some(uri), Some(proxy_type)) = (
                    proxy_data.get("uri").and_then(|v| v.as_str()),
                    proxy_data.get("type").and_then(|v| v.as_str()),
                ) {
                    new_params.insert("proxy".to_string(), uri.to_string());
                    new_params.insert("proxytype".to_string(), proxy_type.to_string());
                }
            }
        }

        // Add remaining params
        new_params.extend(params);

        new_params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_method_base64() {
        let base64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==";
        let result = Utils::get_method(base64_string).await.unwrap();
        assert_eq!(result.get("method").unwrap(), "base64");
        assert_eq!(result.get("body").unwrap(), base64_string);
    }

    #[test]
    fn test_extract_files() {
        let files = vec!["test1.txt".to_string(), "test2.txt".to_string()];
        let result = Utils::extract_files(files, 5);
        // This will fail because files don't exist, but tests the validation logic
        assert!(result.is_err());
    }

    #[test]
    fn test_rename_params() {
        let mut params = HashMap::new();
        params.insert("caseSensitive".to_string(), "1".to_string());
        params.insert("minLen".to_string(), "5".to_string());
        params.insert("url".to_string(), "https://example.com".to_string());

        let result = Utils::rename_params(params);
        assert_eq!(result.get("regsense").unwrap(), "1");
        assert_eq!(result.get("min_len").unwrap(), "5");
        assert_eq!(result.get("pageurl").unwrap(), "https://example.com");
    }
}
