# twocaptcha-rust

[2Captcha](https://2captcha.com/) API client written in Rust.

**Important**: this is an unofficial project. It is a community port of the
[official `2captcha-python` library](https://github.com/2captcha/2captcha-python)
located in the `python/` directory of this repository.

## Installation

Add `twocaptcha` to the `dependencies` section of your `Cargo.toml`:

```toml
[dependencies]
twocaptcha = "0.0.1"
```

## Example

```rust,no_run
use twocaptcha::{TwoCaptcha, RecaptchaVersion};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let solver = TwoCaptcha::new(
        "YOUR_API_KEY".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let mut params = HashMap::new();
    params.insert("min_score".to_string(), "0.3".to_string());

    let result = solver.recaptcha(
        "6LfB5_IbAAAAAMCtsjEHEHKqcB9iQocwwxTiihJu",
        "https://2captcha.com/demo/recaptcha-v3",
        Some(RecaptchaVersion::V3),
        Some(false),
        Some(params),
    ).await?;

    println!("Solved captcha: {}", result.code.unwrap_or_default());
    Ok(())
}
```

More examples can be found in the [`examples`](./examples) directory.

## Supported captcha types

- Normal image captchas
- Audio captchas
- Text captchas
- reCAPTCHA v2 and v3
- FunCaptcha
- GeeTest and GeeTest v4
- hCaptcha
- KeyCaptcha
- atbCAPTCHA
- Capy
- Grid, Canvas, ClickCaptcha and Rotate
- Lemin Cropped Captcha
- Cloudflare Turnstile
- Amazon WAF
- MTCaptcha
- Friendly Captcha
- Cutcaptcha
- Tencent captcha
- DataDome captcha
- CyberSiARA
- Yandex Smart captcha

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE)
file for details.
