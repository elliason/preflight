//! Closed protocol declarations. Adapters classify; the shared core inspects.
use crate::document;
use anyhow::Result;
use axum::http::Uri;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adapter {
    Responses,
    ChatCompletions,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    OpenAi,
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
        // Both legacy routes deliberately discard query strings.
        Ok(self.path.into())
    }

    pub fn classify(self, bytes: &[u8]) -> Result<InspectionPlan> {
        let body = document::parse(bytes)?;
        anyhow::ensure!(body.is_object(), "invalid_json");
        match self.adapter {
            Adapter::Responses | Adapter::ChatCompletions => Ok(InspectionPlan {
                body,
                content: Content::Legacy,
            }),
        }
    }
}
impl Adapter {
    pub fn route(self) -> RouteSpec {
        let path = match self {
            Self::Responses => "/v1/responses",
            Self::ChatCompletions => "/v1/chat/completions",
        };
        RouteSpec {
            adapter: self,
            path,
            family: Family::OpenAi,
        }
    }
}

/// A plan owns the classified body: callers cannot substitute unclassified data.
#[derive(Debug)]
pub struct InspectionPlan {
    pub(crate) body: Value,
    pub(crate) content: Content,
}
#[derive(Debug)]
pub enum Content {
    Legacy,
}
