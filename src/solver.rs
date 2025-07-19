use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use serde_json::Value;
use base64::Engine;

use crate::api::ApiClient;
use crate::error::{TwoCaptchaError, Result};
use crate::types::{AudioLanguage, CaptchaResult, ExtendedResponse, Proxy, RecaptchaVersion, Balance};
use crate::utils::Utils;

/// Main TwoCaptcha solver client
#[derive(Debug, Clone)]
pub struct TwoCaptcha {
    api_key: String,
    soft_id: Option<u32>,
    callback: Option<String>,
    default_timeout: Duration,
    recaptcha_timeout: Duration,
    polling_interval: Duration,
    api_client: ApiClient,
    max_files: usize,
    extended_response: bool,
}

impl TwoCaptcha {
    /// Create a new TwoCaptcha client
    pub fn new(
        api_key: String,
        soft_id: Option<u32>,
        callback: Option<String>,
        default_timeout: Option<Duration>,
        recaptcha_timeout: Option<Duration>,
        polling_interval: Option<Duration>,
        server: Option<String>,
        extended_response: Option<bool>,
    ) -> Self {
        Self {
            api_key,
            soft_id: soft_id.or(Some(4580)),
            callback,
            default_timeout: default_timeout.unwrap_or(Duration::from_secs(120)),
            recaptcha_timeout: recaptcha_timeout.unwrap_or(Duration::from_secs(600)),
            polling_interval: polling_interval.unwrap_or(Duration::from_secs(10)),
            api_client: ApiClient::new(server),
            max_files: 9,
            extended_response: extended_response.unwrap_or(false),
        }
    }

    /// Solve a normal captcha (image)
    pub async fn normal(&self, file: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let method = Utils::get_method(file).await?;
        let mut all_params = method;
        if let Some(p) = params {
            all_params.extend(p);
        }
        self.solve(None, None, all_params).await
    }

    /// Solve an audio captcha
    pub async fn audio(&self, file: &str, lang: AudioLanguage, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let body = if !file.contains('.') && file.len() > 50 {
            // It's a base64 string
            file.to_string()
        } else if file.ends_with(".mp3") && file.starts_with("http") {
            // Download from URL
            let response = reqwest::get(file).await?;
            if response.status() != 200 {
                return Err(TwoCaptchaError::Validation(format!(
                    "File could not be downloaded from url: {}", file
                )));
            }
            let content = response.bytes().await?;
            base64::engine::general_purpose::STANDARD.encode(&content)
        } else if file.ends_with(".mp3") {
            // Read from file
            let content = tokio::fs::read(file).await?;
            base64::engine::general_purpose::STANDARD.encode(&content)
        } else {
            return Err(TwoCaptchaError::Validation(
                "File extension is not .mp3 or it is not a base64 string.".to_string()
            ));
        };

        let mut all_params = HashMap::new();
        all_params.insert("body".to_string(), body);
        all_params.insert("method".to_string(), "audio".to_string());
        all_params.insert("lang".to_string(), lang.as_str().to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve a text captcha
    pub async fn text(&self, text: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("text".to_string(), text.to_string());
        all_params.insert("method".to_string(), "post".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve reCAPTCHA (v2, v3)
    pub async fn recaptcha(
        &self, 
        sitekey: &str, 
        url: &str, 
        version: Option<RecaptchaVersion>,
        enterprise: Option<bool>,
        params: Option<HashMap<String, String>>
    ) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("googlekey".to_string(), sitekey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "userrecaptcha".to_string());
        all_params.insert("version".to_string(), 
            version.unwrap_or(RecaptchaVersion::V2).as_str().to_string());
        all_params.insert("enterprise".to_string(), 
            if enterprise.unwrap_or(false) { "1" } else { "0" }.to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(Some(self.recaptcha_timeout), None, all_params).await
    }

    /// Solve FunCaptcha
    pub async fn funcaptcha(&self, sitekey: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("publickey".to_string(), sitekey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "funcaptcha".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve GeeTest captcha
    pub async fn geetest(&self, gt: &str, challenge: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("gt".to_string(), gt.to_string());
        all_params.insert("challenge".to_string(), challenge.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "geetest".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve hCaptcha
    pub async fn hcaptcha(&self, sitekey: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("sitekey".to_string(), sitekey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "hcaptcha".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve KeyCaptcha
    pub async fn keycaptcha(
        &self,
        s_s_c_user_id: &str,
        s_s_c_session_id: &str,
        s_s_c_web_server_sign: &str,
        s_s_c_web_server_sign2: &str,
        url: &str,
        params: Option<HashMap<String, String>>
    ) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("s_s_c_user_id".to_string(), s_s_c_user_id.to_string());
        all_params.insert("s_s_c_session_id".to_string(), s_s_c_session_id.to_string());
        all_params.insert("s_s_c_web_server_sign".to_string(), s_s_c_web_server_sign.to_string());
        all_params.insert("s_s_c_web_server_sign2".to_string(), s_s_c_web_server_sign2.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "keycaptcha".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve Capy captcha
    pub async fn capy(&self, sitekey: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("captchakey".to_string(), sitekey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "capy".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve grid captcha (image)
    pub async fn grid(&self, file: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let method = Utils::get_method(file).await?;
        let mut all_params = method;
        all_params.insert("recaptcha".to_string(), "1".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve canvas captcha (image)
    pub async fn canvas(&self, file: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let provided_params = params.clone().unwrap_or_default();
        if !provided_params.contains_key("hintText") && !provided_params.contains_key("hintImg") {
            return Err(TwoCaptchaError::Validation(
                "parameters required: hintText and/or hintImg".to_string()
            ));
        }

        let method = Utils::get_method(file).await?;
        let mut all_params = method;
        all_params.insert("recaptcha".to_string(), "1".to_string());
        all_params.insert("canvas".to_string(), "1".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve coordinates captcha (image)
    pub async fn coordinates(&self, file: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let method = Utils::get_method(file).await?;
        let mut all_params = method;
        all_params.insert("coordinatescaptcha".to_string(), "1".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve rotate captcha (image)
    pub async fn rotate(&self, files: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let file_method = Utils::get_method(files).await?;
        let mut all_params = HashMap::new();
        if let Some(file) = file_method.get("file") {
            all_params.insert("file".to_string(), file.clone());
        }
        all_params.insert("method".to_string(), "rotatecaptcha".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve rotate captcha with multiple files
    pub async fn rotate_multiple(&self, files: Vec<String>, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let extracted_files = Utils::extract_files(files, self.max_files)?;
        let mut all_params = HashMap::new();
        all_params.insert("method".to_string(), "rotatecaptcha".to_string());
        
        // Add files as parameters
        all_params.extend(extracted_files);

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve GeeTest v4 captcha
    pub async fn geetest_v4(&self, captcha_id: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("captcha_id".to_string(), captcha_id.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "geetest_v4".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve Lemin Cropped Captcha
    pub async fn lemin(&self, captcha_id: &str, div_id: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("captcha_id".to_string(), captcha_id.to_string());
        all_params.insert("div_id".to_string(), div_id.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "lemin".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve atbCAPTCHA
    pub async fn atb_captcha(&self, app_id: &str, api_server: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("app_id".to_string(), app_id.to_string());
        all_params.insert("api_server".to_string(), api_server.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "atb_captcha".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve Cloudflare Turnstile
    pub async fn turnstile(&self, sitekey: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("sitekey".to_string(), sitekey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "turnstile".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve Amazon WAF
    pub async fn amazon_waf(&self, sitekey: &str, iv: &str, context: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("sitekey".to_string(), sitekey.to_string());
        all_params.insert("iv".to_string(), iv.to_string());
        all_params.insert("context".to_string(), context.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "amazon_waf".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve MTCaptcha
    pub async fn mtcaptcha(&self, sitekey: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("sitekey".to_string(), sitekey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "mt_captcha".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve Friendly Captcha
    pub async fn friendly_captcha(&self, sitekey: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("sitekey".to_string(), sitekey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "friendly_captcha".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve Tencent captcha
    pub async fn tencent(&self, app_id: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("app_id".to_string(), app_id.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "tencent".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve CutCaptcha
    pub async fn cutcaptcha(&self, misery_key: &str, apikey: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("misery_key".to_string(), misery_key.to_string());
        all_params.insert("api_key".to_string(), apikey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "cutcaptcha".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve DataDome Captcha
    pub async fn datadome(&self, captcha_url: &str, pageurl: &str, user_agent: &str, proxy: Proxy, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("method".to_string(), "datadome".to_string());
        all_params.insert("captcha_url".to_string(), captcha_url.to_string());
        all_params.insert("pageurl".to_string(), pageurl.to_string());
        all_params.insert("userAgent".to_string(), user_agent.to_string());
        
        // Handle proxy
        let proxy_json = serde_json::to_string(&proxy)?;
        all_params.insert("proxy".to_string(), proxy_json);

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve CyberSiARA captcha
    pub async fn cybersiara(&self, master_url_id: &str, pageurl: &str, user_agent: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("method".to_string(), "cybersiara".to_string());
        all_params.insert("master_url_id".to_string(), master_url_id.to_string());
        all_params.insert("pageurl".to_string(), pageurl.to_string());
        all_params.insert("userAgent".to_string(), user_agent.to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Solve Yandex Smart captcha
    pub async fn yandex_smart(&self, sitekey: &str, url: &str, params: Option<HashMap<String, String>>) -> Result<CaptchaResult> {
        let mut all_params = HashMap::new();
        all_params.insert("sitekey".to_string(), sitekey.to_string());
        all_params.insert("url".to_string(), url.to_string());
        all_params.insert("method".to_string(), "yandex".to_string());

        if let Some(p) = params {
            all_params.extend(p);
        }

        self.solve(None, None, all_params).await
    }

    /// Main solve method - sends captcha and receives result
    pub async fn solve(
        &self,
        timeout: Option<Duration>,
        polling_interval: Option<Duration>,
        params: HashMap<String, String>
    ) -> Result<CaptchaResult> {
        let id = self.send(params).await?;
        let mut result = CaptchaResult {
            captcha_id: id.clone(),
            code: None,
            extended: None,
        };

        if self.callback.is_none() {
            let timeout = timeout.unwrap_or(self.default_timeout);
            let sleep_interval = polling_interval.unwrap_or(self.polling_interval);

            let code = self.wait_result(&id, timeout, sleep_interval).await?;

            if self.extended_response {
                if let Ok(extended) = serde_json::from_str::<ExtendedResponse>(&code) {
                    let mut extended_map = HashMap::new();
                    extended_map.insert("status".to_string(), serde_json::Value::Number(extended.status.into()));
                    if let Some(request) = extended.request {
                        extended_map.insert("code".to_string(), serde_json::Value::String(request));
                    }
                    if let Some(cookies) = extended.cookies {
                        extended_map.insert("cookies".to_string(), serde_json::to_value(cookies)?);
                    }
                    extended_map.extend(extended.additional);
                    result.extended = Some(extended_map);
                } else {
                    result.code = Some(code);
                }
            } else {
                result.code = Some(code);
            }
        }

        Ok(result)
    }

    /// Wait for captcha result with polling
    async fn wait_result(&self, id: &str, timeout: Duration, polling_interval: Duration) -> Result<String> {
        let start = Instant::now();

        while start.elapsed() < timeout {
            match self.get_result(id).await {
                Ok(result) => return Ok(result),
                Err(TwoCaptchaError::Network(_)) => {
                    sleep(polling_interval).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(TwoCaptchaError::Timeout(format!("timeout {} exceeded", timeout.as_secs())))
    }

    /// Send captcha for solving
    async fn send(&self, mut params: HashMap<String, String>) -> Result<String> {
        params = self.default_params(params);
        params = Utils::rename_params(params);

        let (params, files) = Utils::check_hint_img(params, HashMap::new()).await?;

        let response = if files.is_empty() {
            self.api_client.in_(None, params).await?
        } else {
            // Convert files to bytes
            let mut file_bytes = HashMap::new();
            for (key, path) in files {
                let content = tokio::fs::read(&path).await?;
                file_bytes.insert(key, content);
            }
            self.api_client.in_(Some(file_bytes), params).await?
        };

        if !response.starts_with("OK|") {
            return Err(TwoCaptchaError::Api(format!("cannot recognize response {}", response)));
        }

        Ok(response[3..].to_string())
    }

    /// Get captcha result
    async fn get_result(&self, id: &str) -> Result<String> {
        let mut params = HashMap::new();
        params.insert("key".to_string(), self.api_key.clone());
        params.insert("action".to_string(), "get".to_string());
        params.insert("id".to_string(), id.to_string());

        if self.extended_response {
            params.insert("json".to_string(), "1".to_string());
        }

        let response = self.api_client.res(params).await?;

        if self.extended_response {
            let response_data: Value = serde_json::from_str(&response)?;
            if response_data.get("status").and_then(|v| v.as_i64()) == Some(0) {
                return Err(TwoCaptchaError::Network("CAPTCHA_NOT_READY".to_string()));
            }
            if response_data.get("status").and_then(|v| v.as_i64()) != Some(1) {
                return Err(TwoCaptchaError::Api(format!("Unexpected status in response: {}", response)));
            }
            return Ok(response);
        } else {
            if response == "CAPCHA_NOT_READY" {
                return Err(TwoCaptchaError::Network("CAPTCHA_NOT_READY".to_string()));
            }
            if !response.starts_with("OK|") {
                return Err(TwoCaptchaError::Api(format!("cannot recognize response {}", response)));
            }
            return Ok(response[3..].to_string());
        }
    }

    /// Get account balance
    pub async fn balance(&self) -> Result<Balance> {
        let mut params = HashMap::new();
        params.insert("key".to_string(), self.api_key.clone());
        params.insert("action".to_string(), "getbalance".to_string());

        let response = self.api_client.res(params).await?;
        let balance: f64 = response.parse()
            .map_err(|_| TwoCaptchaError::Api(format!("Invalid balance response: {}", response)))?;
        
        Ok(Balance(balance))
    }

    /// Report captcha result (good/bad)
    pub async fn report(&self, id: &str, correct: bool) -> Result<()> {
        let mut params = HashMap::new();
        params.insert("key".to_string(), self.api_key.clone());
        params.insert("action".to_string(), 
            if correct { "reportgood" } else { "reportbad" }.to_string());
        params.insert("id".to_string(), id.to_string());

        self.api_client.res(params).await?;
        Ok(())
    }

    /// Add default parameters
    fn default_params(&self, mut params: HashMap<String, String>) -> HashMap<String, String> {
        params.insert("key".to_string(), self.api_key.clone());

        if let Some(callback) = &self.callback {
            params.insert("callback".to_string(), callback.clone());
        }

        if let Some(soft_id) = self.soft_id {
            params.insert("softId".to_string(), soft_id.to_string());
        }

        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_twocaptcha_creation() {
        let client = TwoCaptcha::new(
            "test_key".to_string(),
            Some(1234),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        
        assert_eq!(client.api_key, "test_key");
        assert_eq!(client.soft_id, Some(1234));
        assert_eq!(client.max_files, 9);
    }
}
