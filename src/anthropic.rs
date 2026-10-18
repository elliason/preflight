//! Pure classification of the initial Anthropic Messages content matrix.
use crate::{
    document,
    protocol::{Content, InspectionPlan},
};
use anyhow::{Result, bail, ensure};
use serde_json::{Map, Value};

const UNSUPPORTED: document::PlanError = document::PlanError::Unsupported;

/// @cc [owner:ghuntley,label:security] closed-anthropic-content
/// Every supplied field MUST be classified or rejected. Unknown content blocks,
/// opaque provider state and unsupported attachments MUST NOT be approved.
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
        values.iter().map(block).collect::<Result<_>>()?,
    ))
}
fn block(value: &Value) -> Result<Content> {
    let object = object(value)?;
    match object.get("type").and_then(Value::as_str) {
        Some("text") => text_block(value),
        Some("tool_use") => {
            for key in ["id", "name", "input"] {
                ensure!(object.contains_key(key), "invalid_request");
            }
            fields(object, |key, value| match key {
                "type" | "id" | "name" => string_control(value),
                "input" => json_text(value, 0),
                "cache_control" => cache_control(value),
                _ => bail!(UNSUPPORTED),
            })
        }
        Some("tool_result") => {
            ensure!(object.contains_key("tool_use_id"), "invalid_request");
            fields(object, |key, value| match key {
                "type" | "tool_use_id" => string_control(value),
                "content" => text_content(value, 0),
                "is_error" => {
                    ensure!(value.is_boolean(), "invalid_request");
                    Ok(Content::Structural)
                }
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
        Some("redacted_thinking") => Ok(Content::OpaqueGroup),
        Some("image" | "document") => Ok(Content::Attachment),
        _ => Ok(Content::Unsupported),
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
        object.contains_key("name") && object.contains_key("input_schema"),
        UNSUPPORTED
    );
    fields(object, |key, value| match key {
        "name" => string_control(value),
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
