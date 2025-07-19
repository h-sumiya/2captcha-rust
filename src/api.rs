use crate::error::{Result, TwoCaptchaError};
use reqwest::{Client, Response, multipart::Form};
use std::collections::HashMap;

/// API client for communicating with 2captcha service
#[derive(Debug, Clone)]
pub struct ApiClient {
    post_url: String,
    client: Client,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(post_url: Option<String>) -> Self {
        let post_url = post_url.unwrap_or_else(|| "2captcha.com".to_string());
        let client = Client::new();

        Self { post_url, client }
    }

    /// Send POST request to solve captcha
    pub async fn in_(
        &self,
        files: Option<HashMap<String, Vec<u8>>>,
        params: HashMap<String, String>,
    ) -> Result<String> {
        let url = format!("https://{}/in.php", self.post_url);

        let response = if let Some(files) = files {
            // Handle file uploads with multipart form
            let mut form = Form::new();

            // Add regular parameters
            for (key, value) in params {
                form = form.text(key, value);
            }

            // Add files
            for (key, content) in files {
                let part = reqwest::multipart::Part::bytes(content).file_name("file");
                form = form.part(key, part);
            }

            self.client.post(&url).multipart(form).send().await?
        } else if params.contains_key("file") {
            // Handle single file upload
            let file_path = params.get("file").unwrap().clone();
            let mut form_params = params.clone();
            form_params.remove("file");

            let file_content = tokio::fs::read(&file_path)
                .await
                .map_err(|e| TwoCaptchaError::Io(e))?;

            let mut form = Form::new();
            for (key, value) in form_params {
                form = form.text(key, value);
            }

            let part = reqwest::multipart::Part::bytes(file_content).file_name("file");
            form = form.part("file", part);

            self.client.post(&url).multipart(form).send().await?
        } else {
            // Handle regular form data
            self.client.post(&url).form(&params).send().await?
        };

        self.handle_response(response).await
    }

    /// Send GET request for additional operations (get result, balance, report etc.)
    pub async fn res(&self, params: HashMap<String, String>) -> Result<String> {
        let url = format!("https://{}/res.php", self.post_url);
        let response = self.client.get(&url).query(&params).send().await?;

        self.handle_response(response).await
    }

    /// Handle HTTP response and check for errors
    async fn handle_response(&self, response: Response) -> Result<String> {
        if response.status() != 200 {
            return Err(TwoCaptchaError::Network(format!(
                "bad response: {}",
                response.status()
            )));
        }

        let text = response.text().await?;

        if text.contains("ERROR") {
            return Err(TwoCaptchaError::Api(text));
        }

        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client_creation() {
        let client = ApiClient::new(None);
        assert_eq!(client.post_url, "2captcha.com");

        let client = ApiClient::new(Some("custom.domain.com".to_string()));
        assert_eq!(client.post_url, "custom.domain.com");
    }
}
