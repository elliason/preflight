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
