//! Multimodal processing utilities for IronClaw.
//!
//! Provides helpers for handling images, audio, and video content
//! within the agent pipeline, including MIME detection, validation,
//! and provider-specific format conversion.

use anyhow::Result;
use base64::{Engine as Base64Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

use super::types::ContentBlock;

/// Supported image formats.
pub const SUPPORTED_IMAGE_TYPES: &[&str] = &[
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml",
];

/// Supported audio formats.
pub const SUPPORTED_AUDIO_TYPES: &[&str] = &[
    "audio/mp3", "audio/mpeg", "audio/wav", "audio/ogg", "audio/flac", "audio/webm",
];

/// Supported video formats.
pub const SUPPORTED_VIDEO_TYPES: &[&str] = &[
    "video/mp4", "video/webm", "video/mpeg", "video/quicktime",
];

/// Maximum inline image size (10 MB base64).
pub const MAX_IMAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum inline audio size (25 MB base64).
pub const MAX_AUDIO_SIZE: usize = 25 * 1024 * 1024;

/// Detect MIME type from file extension.
pub fn detect_media_type(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?.to_lowercase();
    match ext.as_str() {
        "png" => Some("image/png".into()),
        "jpg" | "jpeg" => Some("image/jpeg".into()),
        "gif" => Some("image/gif".into()),
        "webp" => Some("image/webp".into()),
        "svg" => Some("image/svg+xml".into()),
        "mp3" => Some("audio/mp3".into()),
        "wav" => Some("audio/wav".into()),
        "ogg" => Some("audio/ogg".into()),
        "flac" => Some("audio/flac".into()),
        "mp4" => Some("video/mp4".into()),
        "webm" => Some("video/webm".into()),
        "mov" => Some("video/quicktime".into()),
        "pdf" => Some("application/pdf".into()),
        "txt" => Some("text/plain".into()),
        "json" => Some("application/json".into()),
        _ => None,
    }
}

/// Load a file from disk and create the appropriate ContentBlock.
pub fn load_file_as_content_block(path: &Path) -> Result<ContentBlock> {
    let media_type = detect_media_type(path)
        .ok_or_else(|| anyhow::anyhow!("Unsupported file type: {}", path.display()))?;

    let data = std::fs::read(path)?;
    let encoded = BASE64.encode(&data);
    let size = data.len();

    info!(path = %path.display(), media_type = %media_type, size = size, "Loading file as content block");

    if media_type.starts_with("image/") {
        if size > MAX_IMAGE_SIZE {
            anyhow::bail!("Image too large ({} bytes, max {})", size, MAX_IMAGE_SIZE);
        }
        Ok(ContentBlock::Image {
            data: Some(encoded),
            url: None,
            media_type,
            alt_text: path.file_name().and_then(|n| n.to_str()).map(String::from),
        })
    } else if media_type.starts_with("audio/") {
        if size > MAX_AUDIO_SIZE {
            anyhow::bail!("Audio too large ({} bytes, max {})", size, MAX_AUDIO_SIZE);
        }
        Ok(ContentBlock::Audio {
            data: Some(encoded),
            url: None,
            media_type,
            duration_secs: None,
            transcript: None,
        })
    } else if media_type.starts_with("video/") {
        Ok(ContentBlock::Video {
            url: format!("file://{}", path.display()),
            media_type,
            duration_secs: None,
            thumbnail: None,
            transcript: None,
        })
    } else {
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        Ok(ContentBlock::File {
            data: Some(encoded),
            url: None,
            filename,
            media_type,
            size_bytes: Some(size as u64),
        })
    }
}

/// Validate that a content block's media type is supported.
pub fn validate_content_block(block: &ContentBlock) -> Result<()> {
    match block {
        ContentBlock::Text { text } => {
            if text.is_empty() {
                anyhow::bail!("Empty text content block");
            }
            Ok(())
        }
        ContentBlock::Image { media_type, data, .. } => {
            if !SUPPORTED_IMAGE_TYPES.contains(&media_type.as_str()) {
                anyhow::bail!("Unsupported image type: {}", media_type);
            }
            if let Some(d) = data {
                if d.len() > MAX_IMAGE_SIZE {
                    anyhow::bail!("Image data exceeds maximum size");
                }
            }
            Ok(())
        }
        ContentBlock::Audio { media_type, data, .. } => {
            if !SUPPORTED_AUDIO_TYPES.contains(&media_type.as_str()) {
                anyhow::bail!("Unsupported audio type: {}", media_type);
            }
            if let Some(d) = data {
                if d.len() > MAX_AUDIO_SIZE {
                    anyhow::bail!("Audio data exceeds maximum size");
                }
            }
            Ok(())
        }
        ContentBlock::Video { media_type, .. } => {
            if !SUPPORTED_VIDEO_TYPES.contains(&media_type.as_str()) {
                anyhow::bail!("Unsupported video type: {}", media_type);
            }
            Ok(())
        }
        ContentBlock::File { size_bytes, .. } => {
            if let Some(size) = size_bytes {
                if *size > MAX_AUDIO_SIZE as u64 {
                    anyhow::bail!("File too large");
                }
            }
            Ok(())
        }
    }
}

/// Convert content blocks to Anthropic API format.
pub fn to_anthropic_format(blocks: &[ContentBlock]) -> Vec<serde_json::Value> {
    blocks.iter().map(|block| match block {
        ContentBlock::Text { text } => serde_json::json!({
            "type": "text",
            "text": text
        }),
        ContentBlock::Image { data, url, media_type, .. } => {
            if let Some(data) = data {
                serde_json::json!({
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": data
                    }
                })
            } else if let Some(url) = url {
                serde_json::json!({
                    "type": "image",
                    "source": {
                        "type": "url",
                        "url": url
                    }
                })
            } else {
                serde_json::json!({"type": "text", "text": "[missing image data]"})
            }
        }
        _ => {
            let label = match block {
                ContentBlock::Audio { .. } => "audio",
                ContentBlock::Video { .. } => "video",
                ContentBlock::File { filename, .. } => filename.as_str(),
                _ => "unknown",
            };
            serde_json::json!({
                "type": "text",
                "text": format!("[{} content — not supported by this provider]", label)
            })
        }
    }).collect()
}

/// Convert content blocks to OpenAI-compatible format.
pub fn to_openai_format(blocks: &[ContentBlock]) -> Vec<serde_json::Value> {
    blocks.iter().map(|block| match block {
        ContentBlock::Text { text } => serde_json::json!({
            "type": "text",
            "text": text
        }),
        ContentBlock::Image { data, url, media_type, .. } => {
            if let Some(url) = url {
                serde_json::json!({
                    "type": "image_url",
                    "image_url": { "url": url }
                })
            } else if let Some(data) = data {
                serde_json::json!({
                    "type": "image_url",
                    "image_url": {
                        "url": format!("data:{};base64,{}", media_type, data)
                    }
                })
            } else {
                serde_json::json!({"type": "text", "text": "[missing image]"})
            }
        }
        _ => serde_json::json!({
            "type": "text",
            "text": "[unsupported media type]"
        }),
    }).collect()
}

/// Extract all text from content blocks.
pub fn extract_text(blocks: &[ContentBlock]) -> String {
    blocks.iter()
        .filter_map(|b| b.as_text())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Summary of media types in content blocks for logging.
pub fn media_summary(blocks: &[ContentBlock]) -> String {
    let mut parts = Vec::new();
    let text_count = blocks.iter().filter(|b| matches!(b, ContentBlock::Text { .. })).count();
    let image_count = blocks.iter().filter(|b| matches!(b, ContentBlock::Image { .. })).count();
    let audio_count = blocks.iter().filter(|b| matches!(b, ContentBlock::Audio { .. })).count();
    let video_count = blocks.iter().filter(|b| matches!(b, ContentBlock::Video { .. })).count();
    let file_count = blocks.iter().filter(|b| matches!(b, ContentBlock::File { .. })).count();

    if text_count > 0 { parts.push(format!("{} text", text_count)); }
    if image_count > 0 { parts.push(format!("{} image", image_count)); }
    if audio_count > 0 { parts.push(format!("{} audio", audio_count)); }
    if video_count > 0 { parts.push(format!("{} video", video_count)); }
    if file_count > 0 { parts.push(format!("{} file", file_count)); }

    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_media_type_png() {
        let path = Path::new("photo.png");
        assert_eq!(detect_media_type(path), Some("image/png".to_string()));
    }

    #[test]
    fn test_detect_media_type_jpeg() {
        assert_eq!(detect_media_type(Path::new("pic.jpg")), Some("image/jpeg".into()));
        assert_eq!(detect_media_type(Path::new("pic.jpeg")), Some("image/jpeg".into()));
    }

    #[test]
    fn test_detect_media_type_mp3() {
        assert_eq!(detect_media_type(Path::new("song.mp3")), Some("audio/mp3".into()));
    }

    #[test]
    fn test_detect_media_type_mp4() {
        assert_eq!(detect_media_type(Path::new("vid.mp4")), Some("video/mp4".into()));
    }

    #[test]
    fn test_detect_media_type_unknown() {
        assert_eq!(detect_media_type(Path::new("file.xyz")), None);
    }

    #[test]
    fn test_validate_text_block() {
        assert!(validate_content_block(&ContentBlock::text("hello")).is_ok());
        assert!(validate_content_block(&ContentBlock::Text { text: String::new() }).is_err());
    }

    #[test]
    fn test_validate_image_block() {
        let block = ContentBlock::image_base64("abc".into(), "image/png");
        assert!(validate_content_block(&block).is_ok());

        let bad = ContentBlock::image_base64("abc".into(), "image/bmp");
        assert!(validate_content_block(&bad).is_err());
    }

    #[test]
    fn test_validate_unsupported_video_type() {
        let block = ContentBlock::video_url("http://x".into(), "video/avi");
        assert!(validate_content_block(&block).is_err());
    }

    #[test]
    fn test_to_anthropic_format_text() {
        let blocks = vec![ContentBlock::text("hello")];
        let result = to_anthropic_format(&blocks);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["type"], "text");
        assert_eq!(result[0]["text"], "hello");
    }

    #[test]
    fn test_to_anthropic_format_image() {
        let blocks = vec![ContentBlock::image_base64("data123".into(), "image/png")];
        let result = to_anthropic_format(&blocks);
        assert_eq!(result[0]["type"], "image");
        assert_eq!(result[0]["source"]["type"], "base64");
    }

    #[test]
    fn test_to_openai_format_text() {
        let blocks = vec![ContentBlock::text("world")];
        let result = to_openai_format(&blocks);
        assert_eq!(result[0]["type"], "text");
        assert_eq!(result[0]["text"], "world");
    }

    #[test]
    fn test_to_openai_format_image_url() {
        let blocks = vec![ContentBlock::image_url("http://img.png".into(), "image/png")];
        let result = to_openai_format(&blocks);
        assert_eq!(result[0]["type"], "image_url");
        assert_eq!(result[0]["image_url"]["url"], "http://img.png");
    }

    #[test]
    fn test_extract_text() {
        let blocks = vec![
            ContentBlock::text("hello"),
            ContentBlock::image_base64("data".into(), "image/png"),
            ContentBlock::text("world"),
        ];
        assert_eq!(extract_text(&blocks), "hello\nworld");
    }

    #[test]
    fn test_media_summary() {
        let blocks = vec![
            ContentBlock::text("hi"),
            ContentBlock::image_base64("d".into(), "image/png"),
            ContentBlock::image_url("u".into(), "image/jpeg"),
            ContentBlock::audio_base64("a".into(), "audio/mp3"),
        ];
        let summary = media_summary(&blocks);
        assert!(summary.contains("1 text"));
        assert!(summary.contains("2 image"));
        assert!(summary.contains("1 audio"));
    }

    #[test]
    fn test_load_nonexistent_file_error() {
        let result = load_file_as_content_block(Path::new("/nonexistent/file.png"));
        assert!(result.is_err());
    }
}
