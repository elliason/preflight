//! Closed classification of Anthropic Messages content and attachment sources.
use crate::{
    document,
    protocol::{AttachmentSource, Content, InspectionPlan, MediaType},
};
use anyhow::{Result, bail, ensure};
use serde_json::{Map, Value};

const UNSUPPORTED: document::PlanError = document::PlanError::Unsupported;

/// @cc [owner:ghuntley,label:security] closed-anthropic-content
/// Every supplied field MUST be classified or rejected. Unknown content blocks,
/// opaque provider state and unsupported attachments MUST NOT be approved.
/// Nested result types MUST occur only under their declared parent block.
pub fn classify(body: Value) -> Result<InspectionPlan> {
    let root = object(&body)?;
    ensure!(
        root.get("model").is_some_and(Value::is_string),
        "invalid_request"
    );
    ensure!(root.contains_key("messages"), "invalid_request");
    let content = fields(root, |key, value| match key {
        "system" => text_content(value, 0),
        "messages" => array(value, |message| {
            let message = object(message)?;
            ensure!(
                matches!(
                    message.get("role").and_then(Value::as_str),
                    Some("user" | "assistant")
                ),
                "invalid_request"
            );
            ensure!(message.contains_key("content"), "invalid_request");
            fields(message, |key, value| match key {
                "role" => Ok(Content::Structural),
                "content" => message_content(value),
                _ => bail!(UNSUPPORTED),
            })
        }),
        "tools" => array(value, tool),
        "context_management" => context_management(value),
        "output_config" => output_config(value),
        "model" | "max_tokens" | "stream" | "temperature" | "top_k" | "top_p"
        | "stop_sequences" | "metadata" | "tool_choice" | "thinking" => structural(value, 0),
        _ => bail!(UNSUPPORTED),
    })?;
    Ok(InspectionPlan { body, content })
}

fn context_management(value: &Value) -> Result<Content> {
    fields(object(value)?, |key, value| match key {
        "edits" => array(value, |edit| {
            let edit = object(edit)?;
            ensure!(
                edit.get("type").and_then(Value::as_str) == Some("clear_thinking_20251015")
                    && edit.get("keep").and_then(Value::as_str) == Some("all"),
                UNSUPPORTED
            );
            fields(edit, |key, value| match key {
                "type" | "keep" => string_control(value),
                _ => bail!(UNSUPPORTED),
            })
        }),
        _ => bail!(UNSUPPORTED),
    })
}

fn output_config(value: &Value) -> Result<Content> {
    fields(object(value)?, |key, value| match key {
        "effort" => {
            ensure!(
                matches!(value.as_str(), Some("low" | "medium" | "high" | "max")),
                "invalid_request"
            );
            Ok(Content::Structural)
        }
        _ => bail!(UNSUPPORTED),
    })
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid_request"))
}

fn fields(
    object: &Map<String, Value>,
    classify: impl Fn(&str, &Value) -> Result<Content>,
) -> Result<Content> {
    Ok(Content::Object(
        object
            .iter()
            .map(|(key, value)| Ok((key.clone(), classify(key, value)?)))
            .collect::<Result<_>>()?,
    ))
}
fn array(value: &Value, classify: impl Fn(&Value) -> Result<Content>) -> Result<Content> {
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid_request"))?;
    Ok(Content::Array(
        values.iter().map(classify).collect::<Result<_>>()?,
    ))
}
fn text(value: &Value) -> Result<Content> {
    ensure!(value.is_string(), "invalid_request");
    Ok(Content::EditableText)
}
fn string_control(value: &Value) -> Result<Content> {
    ensure!(value.is_string(), "invalid_request");
    Ok(Content::Structural)
}
fn structural(value: &Value, depth: usize) -> Result<Content> {
    bound(depth)?;
    match value {
        Value::Object(values) => {
            for value in values.values() {
                structural(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                structural(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(Content::Structural)
}
fn bound(depth: usize) -> Result<()> {
    ensure!(depth <= 64, "nesting_limit");
    Ok(())
}

fn text_block(value: &Value) -> Result<Content> {
    let object = object(value)?;
    ensure!(
        object.get("type").and_then(Value::as_str) == Some("text"),
        UNSUPPORTED
    );
    ensure!(object.contains_key("text"), "invalid_request");
    fields(object, |key, value| match key {
        "type" => string_control(value),
        "text" => text(value),
        "cache_control" => cache_control(value),
        "citations" => array(value, citation),
        _ => bail!(UNSUPPORTED),
    })
}
fn text_content(value: &Value, depth: usize) -> Result<Content> {
    bound(depth)?;
    if value.is_string() {
        return text(value);
    }
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid_request"))?;
    Ok(Content::TextBlocks(
        values.iter().map(text_block).collect::<Result<_>>()?,
    ))
}
fn message_content(value: &Value) -> Result<Content> {
    if value.is_string() {
        return text(value);
    }
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid_request"))?;
    Ok(Content::TextBlocks(
        values.iter().map(message_block).collect::<Result<_>>()?,
    ))
}
fn message_block(value: &Value) -> Result<Content> {
    // These are nested-only result/error types, never message content blocks.
    match value.get("type").and_then(Value::as_str) {
        Some(
            "web_fetch_result"
            | "code_execution_result"
            | "bash_code_execution_result"
            | "text_editor_code_execution_view_result"
            | "text_editor_code_execution_create_result"
            | "text_editor_code_execution_str_replace_result"
            | "tool_search_tool_search_result"
            | "web_search_tool_result_error"
            | "web_fetch_tool_result_error"
            | "code_execution_tool_result_error"
            | "bash_code_execution_tool_result_error"
            | "text_editor_code_execution_tool_result_error"
            | "tool_search_tool_result_error",
        ) => reject("nested result block requires its matching parent"),
        _ => block(value),
    }
}

fn child_block(value: &Value, allowed: &[&str]) -> Result<Content> {
    if !value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| allowed.contains(&kind))
    {
        return reject("content block type is unsupported for this parent");
    }
    block(value)
}

fn server_result(value: &Value, parent: &str) -> Result<Content> {
    let allowed: &[&str] = match parent {
        "web_search_tool_result" => {
            return if value.is_array() {
                array(value, |child| child_block(child, &["web_search_result"]))
            } else {
                child_block(value, &["web_search_tool_result_error"])
            };
        }
        "web_fetch_tool_result" => &["web_fetch_result", "web_fetch_tool_result_error"],
        "code_execution_tool_result" => &[
            "code_execution_result",
            "code_execution_tool_result_error",
            "encrypted_code_execution_result",
        ],
        "bash_code_execution_tool_result" => &[
            "bash_code_execution_result",
            "bash_code_execution_tool_result_error",
        ],
        "text_editor_code_execution_tool_result" => &[
            "text_editor_code_execution_view_result",
            "text_editor_code_execution_create_result",
            "text_editor_code_execution_str_replace_result",
            "text_editor_code_execution_tool_result_error",
        ],
        "tool_search_tool_result" => &[
            "tool_search_tool_search_result",
            "tool_search_tool_result_error",
        ],
        _ => return reject("server result parent is unsupported"),
    };
    child_block(value, allowed)
}

fn block(value: &Value) -> Result<Content> {
    let object = object(value)?;
    let kind = object.get("type").and_then(Value::as_str);
    // Static reasons never echo user-supplied type names or field contents.
    match kind {
        Some("web_search_result") => {
            return reject("web_search_result requires opaque encrypted_content");
        }
        Some("redacted_thinking") => return reject("redacted_thinking contains opaque data"),
        Some("encrypted_code_execution_result") => {
            return reject("encrypted_code_execution_result contains opaque output");
        }
        Some("container_upload") => return reject("container_upload is an unresolved reference"),
        Some("tool_reference") => return reject("tool_reference is an unresolved reference"),
        Some("code_execution_output") => {
            return reject("code_execution_output is an unresolved file reference");
        }
        Some("bash_code_execution_output") => {
            return reject("bash_code_execution_output is an unresolved file reference");
        }
        Some("mcp_tool_listing") => return reject("mcp_tool_listing is unsupported"),
        Some("advisor_tool_result" | "advisor_result" | "advisor_redacted_result") => {
            return reject("advisor_tool_result and advisor results are unsupported");
        }
        Some("browser_state") => return reject("browser_state is unsupported"),
        Some("fallback") => return reject("fallback is unsupported"),
        _ => {}
    }
    if object.keys().any(|k| {
        matches!(
            k.as_str(),
            "encrypted_content" | "encrypted_index" | "encrypted_stdout"
        )
    }) {
        return reject("content block contains opaque provider state");
    }
    if kind == Some("text_editor_code_execution_view_result")
        && object.get("file_type").and_then(Value::as_str) != Some("text")
    {
        return reject("text_editor_code_execution_view_result supports only text file_type");
    }
    let required: &[&str] = match kind {
        Some("search_result") => &["source", "title", "content"],
        Some("web_fetch_result") => &["url", "content"],
        Some(
            "web_search_tool_result"
            | "web_fetch_tool_result"
            | "code_execution_tool_result"
            | "bash_code_execution_tool_result"
            | "text_editor_code_execution_tool_result"
            | "tool_search_tool_result",
        ) => &["tool_use_id", "content"],
        Some("code_execution_result" | "bash_code_execution_result") => {
            &["stdout", "stderr", "return_code", "content"]
        }
        Some("text_editor_code_execution_view_result") => &["content", "file_type"],
        Some("text_editor_code_execution_create_result") => &["is_file_update"],
        Some("tool_search_tool_search_result") => &["tool_references"],
        Some("compaction") => &["content"],
        Some(
            "web_search_tool_result_error"
            | "web_fetch_tool_result_error"
            | "code_execution_tool_result_error"
            | "bash_code_execution_tool_result_error"
            | "text_editor_code_execution_tool_result_error"
            | "tool_search_tool_result_error",
        ) => &["error_code"],
        _ => &[],
    };
    ensure!(
        required.iter().all(|key| object.contains_key(*key)),
        "invalid_request"
    );
    match kind {
        Some("text") => text_block(value),
        Some("tool_use" | "server_tool_use" | "mcp_tool_use") => {
            for key in ["id", "name", "input"] {
                ensure!(object.contains_key(key), "invalid_request");
            }
            fields(object, |key, value| match key {
                "type" | "id" | "name" | "server_name" => string_control(value),
                "caller" => structural(value, 0),
                "input" => json_text(value, 0),
                "cache_control" => cache_control(value),
                _ => bail!(UNSUPPORTED),
            })
        }
        Some("tool_result" | "mcp_tool_result") => {
            ensure!(object.contains_key("tool_use_id"), "invalid_request");
            fields(object, |key, value| match key {
                "type" | "tool_use_id" => string_control(value),
                "content" => result_content(value, kind == Some("mcp_tool_result")),
                "is_error" => boolean(value),
                "cache_control" => cache_control(value),
                _ => bail!(UNSUPPORTED),
            })
        }
        Some("thinking") => {
            ensure!(
                object.len() == 3
                    && object.get("thinking").is_some_and(Value::is_string)
                    && object.get("signature").is_some_and(Value::is_string),
                UNSUPPORTED
            );
            Ok(Content::SignedGroup)
        }
        Some("image") => media_block(value, true),
        Some("document") => media_block(value, false),
        Some("search_result") => fields(object, |key, value| match key {
            "type" => string_control(value),
            "title" | "source" => text(value),
            "content" => text_content(value, 0),
            "citations" => citation_config(value),
            "cache_control" => cache_control(value),
            _ => bail!(UNSUPPORTED),
        }),
        Some(
            "web_search_tool_result"
            | "web_fetch_tool_result"
            | "code_execution_tool_result"
            | "bash_code_execution_tool_result"
            | "text_editor_code_execution_tool_result"
            | "tool_search_tool_result",
        ) => fields(object, |key, value| match key {
            "type" | "tool_use_id" => string_control(value),
            "content" => server_result(value, kind.unwrap()),
            "cache_control" => cache_control(value),
            _ => bail!(UNSUPPORTED),
        }),
        Some("web_fetch_result") => fields(object, |key, value| match key {
            "type" | "retrieved_at" => string_control(value),
            "url" => text(value),
            "content" => media_block(value, false),
            _ => bail!(UNSUPPORTED),
        }),
        Some("code_execution_result" | "bash_code_execution_result") => {
            fields(object, |key, value| match key {
                "type" => string_control(value),
                "stdout" | "stderr" => text(value),
                "return_code" => integer(value),
                "content" => array(value, |child| {
                    child_block(
                        child,
                        if kind == Some("code_execution_result") {
                            &["code_execution_output"]
                        } else {
                            &["bash_code_execution_output"]
                        },
                    )
                }),
                _ => bail!(UNSUPPORTED),
            })
        }
        Some("text_editor_code_execution_view_result") => fields(object, |key, value| match key {
            "type" | "file_type" => string_control(value),
            "content" => text(value),
            "num_lines" | "start_line" | "total_lines" => nullable(value, integer),
            _ => bail!(UNSUPPORTED),
        }),
        Some("text_editor_code_execution_create_result") => {
            fields(object, |key, value| match key {
                "type" => string_control(value),
                "is_file_update" => boolean(value),
                _ => bail!(UNSUPPORTED),
            })
        }
        Some("text_editor_code_execution_str_replace_result") => {
            fields(object, |key, value| match key {
                "type" => string_control(value),
                "lines" => nullable(value, |value| {
                    let lines = value
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("invalid_request"))?;
                    Ok(Content::TextLines(
                        lines.iter().map(text).collect::<Result<_>>()?,
                    ))
                }),
                "new_lines" | "new_start" | "old_lines" | "old_start" => nullable(value, integer),
                _ => bail!(UNSUPPORTED),
            })
        }
        Some("tool_search_tool_search_result") => fields(object, |key, value| match key {
            "type" => string_control(value),
            "tool_references" => array(value, |child| child_block(child, &["tool_reference"])),
            _ => bail!(UNSUPPORTED),
        }),
        Some(
            "web_search_tool_result_error"
            | "web_fetch_tool_result_error"
            | "code_execution_tool_result_error"
            | "bash_code_execution_tool_result_error"
            | "text_editor_code_execution_tool_result_error"
            | "tool_search_tool_result_error",
        ) => fields(object, |key, value| match key {
            "type" | "error_code" => string_control(value),
            "error_message" => text(value),
            _ => bail!(UNSUPPORTED),
        }),
        Some("compaction") => fields(object, |key, value| match key {
            "type" => string_control(value),
            "content" => nullable(value, text),
            "cache_control" => cache_control(value),
            _ => bail!(UNSUPPORTED),
        }),
        _ => reject("unknown content block type is unsupported"),
    }
}

fn reject<T>(reason: &'static str) -> Result<T> {
    Err(document::PlanError::Content(reason).into())
}
fn boolean(value: &Value) -> Result<Content> {
    ensure!(value.is_boolean(), "invalid_request");
    Ok(Content::Structural)
}
fn integer(value: &Value) -> Result<Content> {
    ensure!(value.is_i64() || value.is_u64(), "invalid_request");
    Ok(Content::Structural)
}
fn nullable(value: &Value, classify: impl Fn(&Value) -> Result<Content>) -> Result<Content> {
    if value.is_null() {
        Ok(Content::Structural)
    } else {
        classify(value)
    }
}
fn result_content(value: &Value, mcp: bool) -> Result<Content> {
    if value.is_string() {
        return json_text(value, 0);
    }
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid_request"))?;
    Ok(Content::TextBlocks(
        values
            .iter()
            .map(|part| {
                child_block(
                    part,
                    if mcp {
                        &["text"]
                    } else {
                        &[
                            "text",
                            "image",
                            "document",
                            "search_result",
                            "container_upload",
                            "tool_reference",
                        ]
                    },
                )
            })
            .collect::<Result<_>>()?,
    ))
}
fn citation_config(value: &Value) -> Result<Content> {
    fields(object(value)?, |key, value| match key {
        "enabled" => boolean(value),
        _ => bail!(UNSUPPORTED),
    })
}
fn citation(value: &Value) -> Result<Content> {
    let object = object(value)?;
    if object.get("type").and_then(Value::as_str) == Some("web_search_result_location") {
        return reject("web_search_result_location requires opaque encrypted_index");
    }
    if object.contains_key("encrypted_index") {
        return reject("text citation contains opaque encrypted_index");
    }
    ensure!(
        matches!(
            object.get("type").and_then(Value::as_str),
            Some(
                "char_location"
                    | "page_location"
                    | "content_block_location"
                    | "search_result_location"
            )
        ),
        UNSUPPORTED
    );
    fields(object, |key, value| match key {
        "type" => string_control(value),
        "cited_text" | "document_title" | "title" | "url" | "source" => {
            if value.is_null() {
                Ok(Content::Structural)
            } else {
                text(value)
            }
        }
        "document_index"
        | "start_char_index"
        | "end_char_index"
        | "start_page_number"
        | "end_page_number"
        | "start_block_index"
        | "end_block_index"
        | "search_result_index" => integer(value),
        _ => bail!(UNSUPPORTED),
    })
}
fn media_block(value: &Value, image: bool) -> Result<Content> {
    let object = object(value)?;
    ensure!(
        object.get("type").and_then(Value::as_str)
            == Some(if image { "image" } else { "document" }),
        UNSUPPORTED
    );
    if object.contains_key("file_id") {
        return reject("image/document file_id is an unresolved reference");
    }
    ensure!(object.contains_key("source"), "invalid_request");
    fields(object, |key, value| match key {
        "type" => string_control(value),
        "source" => source(value, image),
        "cache_control" => cache_control(value),
        "title" | "context" if !image => nullable(value, text),
        "citations" if !image => citation_config(value),
        _ => bail!(UNSUPPORTED),
    })
}

/// @cc [owner:ghuntley,label:security] native-source-classification
/// Only declared source shapes MAY reach acquisition. Files references and
/// unsupported image formats MUST reject before any upstream request is sent.
fn source(value: &Value, image: bool) -> Result<Content> {
    let object = object(value)?;
    if object.contains_key("file_id") || object.get("type").and_then(Value::as_str) == Some("file")
    {
        return reject("image/document file_id is an unresolved reference");
    }
    match object.get("type").and_then(Value::as_str) {
        Some("base64") => {
            ensure!(
                object.len() == 3 && object.get("data").is_some_and(Value::is_string),
                "invalid_request"
            );
            let media = match object.get("media_type").and_then(Value::as_str) {
                Some("image/png") if image => MediaType::Png,
                Some("image/jpeg") if image => MediaType::Jpeg,
                Some("application/pdf") if !image => MediaType::Pdf,
                Some("image/gif") => {
                    return reject("image GIF is unsupported by the attachment inspector");
                }
                Some("image/webp") => {
                    return reject("image WebP is unsupported by the attachment inspector");
                }
                _ => return reject("image/document media_type is unsupported"),
            };
            Ok(Content::Attachment(AttachmentSource::Base64(media)))
        }
        Some("url") => {
            ensure!(
                object.len() == 2 && object.get("url").is_some_and(Value::is_string),
                "invalid_request"
            );
            Ok(Content::Attachment(AttachmentSource::Url { image }))
        }
        Some("text") if !image => {
            ensure!(
                object.len() == 3
                    && object.get("media_type").and_then(Value::as_str) == Some("text/plain"),
                UNSUPPORTED
            );
            fields(object, |key, value| match key {
                "type" | "media_type" => string_control(value),
                "data" => text(value),
                _ => bail!(UNSUPPORTED),
            })
        }
        Some("content") if !image => {
            ensure!(
                object.len() == 2 && object.contains_key("content"),
                UNSUPPORTED
            );
            fields(object, |key, value| match key {
                "type" => string_control(value),
                "content" if value.is_string() => text(value),
                "content" => {
                    let parts = value
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("invalid_request"))?;
                    Ok(Content::TextBlocks(
                        parts
                            .iter()
                            .map(|part| match part.get("type").and_then(Value::as_str) {
                                Some("text") => text_block(part),
                                Some("image") => media_block(part, true),
                                _ => reject("document content accepts only text and image blocks"),
                            })
                            .collect::<Result<_>>()?,
                    ))
                }
                _ => bail!(UNSUPPORTED),
            })
        }
        _ => reject("image/document source type is unsupported"),
    }
}
fn cache_control(value: &Value) -> Result<Content> {
    fields(object(value)?, |key, value| match key {
        "type" | "ttl" | "scope" => string_control(value),
        _ => bail!(UNSUPPORTED),
    })
}
fn tool(value: &Value) -> Result<Content> {
    let object = object(value)?;
    ensure!(
        object.contains_key("name")
            && (object.contains_key("input_schema")
                || object
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| matches!(
                        kind,
                        "web_search_20250305"
                            | "web_search_20260209"
                            | "web_fetch_20250910"
                            | "web_fetch_20260209"
                            | "code_execution_20250522"
                            | "code_execution_20250825"
                            | "code_execution_20260120"
                            | "bash_20250124"
                            | "text_editor_20250124"
                            | "text_editor_20250429"
                            | "text_editor_20250728"
                            | "tool_search_tool_bm25_20251119"
                            | "tool_search_tool_regex_20251119"
                    ))),
        UNSUPPORTED
    );
    fields(object, |key, value| match key {
        "name" | "type" => string_control(value),
        "strict" | "defer_loading" => boolean(value),
        "max_uses" | "max_content_tokens" => integer(value),
        "allowed_domains" | "blocked_domains" | "allowed_callers" | "user_location" => {
            structural(value, 0)
        }
        "citations" => citation_config(value),
        "description" => text(value),
        "input_schema" => schema(value, 0),
        "cache_control" => cache_control(value),
        _ => bail!(UNSUPPORTED),
    })
}
fn schema(value: &Value, depth: usize) -> Result<Content> {
    bound(depth)?;
    if value.is_boolean() {
        return Ok(Content::Structural);
    }
    fields(object(value)?, |key, value| match key {
        "description" | "title" => text(value),
        "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas" => {
            fields(object(value)?, |_, value| schema(value, depth + 1))
        }
        "items"
        | "additionalProperties"
        | "contains"
        | "not"
        | "if"
        | "then"
        | "else"
        | "propertyNames" => schema(value, depth + 1),
        "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
            array(value, |value| schema(value, depth + 1))
        }
        // Constraints (including enum/const) must never change meaning.
        _ => structural(value, depth + 1),
    })
}
/// @cc [owner:ghuntley,label:security] tool-input-string-fallback
/// Tool strings containing JSON objects or arrays MUST be inspected recursively.
/// Strings that are not valid unique-key JSON MUST remain editable text and be scanned.
fn json_text(value: &Value, depth: usize) -> Result<Content> {
    bound(depth)?;
    match value {
        Value::String(text) => {
            if matches!(text.trim_start().chars().next(), Some('{' | '['))
                && let Ok(body) = document::parse(text.as_bytes())
            {
                let content = json_text(&body, depth + 1)?;
                Ok(Content::JsonText(Box::new(InspectionPlan {
                    body,
                    content,
                })))
            } else {
                Ok(Content::EditableText)
            }
        }
        Value::Object(values) => fields(values, |_, value| json_text(value, depth + 1)),
        Value::Array(_) => array(value, |value| json_text(value, depth + 1)),
        _ => Ok(Content::Structural),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::{TestCase, generators as gs};

    fn leaves(value: &Value) -> usize {
        match value {
            Value::Object(values) => values.values().map(leaves).sum(),
            Value::Array(values) => values.iter().map(leaves).sum(),
            _ => 1,
        }
    }
    fn account(value: &Value, content: &Content) -> usize {
        match content {
            Content::Object(fields) => {
                assert_eq!(value.as_object().unwrap().len(), fields.len());
                fields
                    .iter()
                    .map(|(key, content)| account(&value[key], content))
                    .sum()
            }
            Content::Array(parts) | Content::TextBlocks(parts) | Content::TextLines(parts) => {
                assert_eq!(value.as_array().unwrap().len(), parts.len());
                value
                    .as_array()
                    .unwrap()
                    .iter()
                    .zip(parts)
                    .map(|(value, content)| account(value, content))
                    .sum()
            }
            Content::EditableText | Content::JsonText(_) => {
                assert!(value.is_string());
                1
            }
            Content::Structural | Content::SignedGroup | Content::Attachment(_) => leaves(value),
            _ => panic!("unsupported plan cannot account for content"),
        }
    }
    #[hegel::test]
    fn classification_accounts_for_every_matrix_leaf(tc: TestCase) {
        let matrix: Value =
            serde_json::from_str(include_str!("../tests/fixtures/anthropic-content.json")).unwrap();
        let blocks = matrix["accepted"].as_array().unwrap();
        let block = &blocks[tc.draw(
            gs::integers::<usize>()
                .min_value(0)
                .max_value(blocks.len() - 1),
        )];
        let body =
            serde_json::json!({"model":"fixture","messages":[{"role":"user","content":[block]}]});
        let plan = classify(body).unwrap();
        assert_eq!(account(&plan.body, &plan.content), leaves(&plan.body));
    }
    #[hegel::test]
    fn typed_attachment_sources_account_for_encoded_and_control_leaves(tc: TestCase) {
        let image = tc.draw(gs::integers::<u8>().min_value(0).max_value(1)) == 1;
        let data = tc.draw(gs::text());
        let block = serde_json::json!({"type":if image {"image"} else {"document"},"source":{"type":"base64","media_type":if image {"image/png"} else {"application/pdf"},"data":data}});
        let body =
            serde_json::json!({"model":"fixture","messages":[{"role":"user","content":[block]}]});
        let plan = classify(body).unwrap();
        assert_eq!(account(&plan.body, &plan.content), leaves(&plan.body));
    }
}
