use anyhow::{Context, Result};
use base64::Engine as _;

pub fn decode_base64(value: &str, description: &str) -> Result<Vec<u8>> {
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(decoded) = engine.decode(value) {
            return Ok(decoded);
        }
    }
    Err(anyhow::anyhow!("invalid base64")).with_context(|| description.to_owned())
}
