//! Closed protocol declarations. Adapters classify; the shared core inspects.
use crate::{anthropic, document};
use anyhow::Result;
use axum::http::Uri;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adapter {
    Responses,
    ChatCompletions,
    Messages,
    CountTokens,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    OpenAi,
    Anthropic,
}
#[derive(Clone, Copy, Debug)]
pub struct RouteSpec {
    pub adapter: Adapter,
    pub path: &'static str,
    pub family: Family,
}
impl RouteSpec {
    pub fn target(self, uri: &Uri) -> Result<String> {
        anyhow::ensure!(uri.path() == self.path, "invalid_route");
        match (self.family, uri.query()) {
            (Family::OpenAi, _) | (Family::Anthropic, None) => Ok(self.path.into()),
            (Family::Anthropic, Some("beta=true")) => Ok(format!("{}?beta=true", self.path)),
            _ => anyhow::bail!("invalid_query"),
        }
    }

    pub fn classify(self, bytes: &[u8]) -> Result<InspectionPlan> {
        let body = document::parse(bytes)?;
        anyhow::ensure!(body.is_object(), "invalid_json");
        match self.adapter {
            Adapter::Responses | Adapter::ChatCompletions => Ok(InspectionPlan {
                body,
                content: Content::Legacy,
            }),
            Adapter::Messages | Adapter::CountTokens => anthropic::classify(body),
        }
    }
}
impl Adapter {
    pub fn route(self) -> RouteSpec {
        let (path, family) = match self {
            Self::Responses => ("/v1/responses", Family::OpenAi),
            Self::ChatCompletions => ("/v1/chat/completions", Family::OpenAi),
            Self::Messages => ("/v1/messages", Family::Anthropic),
            Self::CountTokens => ("/v1/messages/count_tokens", Family::Anthropic),
        };
        RouteSpec {
            adapter: self,
            path,
            family,
        }
    }
}

/// @cc [owner:ghuntley,label:security] native-discovery-query
/// Native model discovery MUST forward only bounded, unique, declared query
/// parameters, preserving the validated query bytes. Unknown encodings reject.
pub fn models_target(uri: &Uri) -> Result<String> {
    anyhow::ensure!(uri.path() == "/v1/models", "invalid_route");
    if let Some(query) = uri.query() {
        anyhow::ensure!(!query.is_empty() && query.len() <= 1024, "invalid_query");
        let mut seen = std::collections::HashSet::new();
        for pair in query.split('&') {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid_query"))?;
            anyhow::ensure!(seen.insert(key), "invalid_query");
            let valid = match key {
                "beta" => value == "true",
                "limit" => {
                    !value.is_empty()
                        && value.bytes().all(|b| b.is_ascii_digit())
                        && value
                            .parse::<u16>()
                            .is_ok_and(|limit| (1..=1000).contains(&limit))
                }
                "before_id" | "after_id" => {
                    !value.is_empty()
                        && value.len() <= 256
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                }
                _ => false,
            };
            anyhow::ensure!(valid, "invalid_query");
        }
        anyhow::ensure!(
            !(seen.contains("before_id") && seen.contains("after_id")),
            "invalid_query"
        );
        Ok(format!("/v1/models?{query}"))
    } else {
        Ok("/v1/models".into())
    }
}

/// A plan owns the classified body: callers cannot substitute unclassified data.
/// Object keys and array indices form structural paths, never JSONPath strings.
#[derive(Debug)]
pub struct InspectionPlan {
    pub(crate) body: Value,
    pub(crate) content: Content,
}
#[derive(Debug)]
pub enum Content {
    Legacy,
    EditableText,
    JsonText(Box<InspectionPlan>),
    Structural,
    Object(Vec<(String, Content)>),
    Array(Vec<Content>),
    TextBlocks(Vec<Content>),
    TextLines(Vec<Content>),
    SignedGroup,
    OpaqueGroup,
    Attachment(AttachmentSource),
    /// Payload bytes have completed inspection; only source controls remain scan-only.
    InspectedSource,
    Unsupported,
}

#[derive(Clone, Copy, Debug)]
pub enum AttachmentSource {
    Base64(MediaType),
    Url { image: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaType {
    Jpeg,
    Png,
    Pdf,
    Text,
}
impl MediaType {
    pub fn mime(self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Pdf => "application/pdf",
            Self::Text => "text/plain",
        }
    }
    pub fn detect(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(Self::Png)
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            Some(Self::Jpeg)
        } else if bytes.starts_with(b"%PDF-") {
            Some(Self::Pdf)
        } else if std::str::from_utf8(bytes).is_ok_and(|s| {
            s.chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        }) {
            Some(Self::Text)
        } else {
            None
        }
    }
}
