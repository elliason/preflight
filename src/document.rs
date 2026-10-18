use crate::{attachments::Attachments, scanner::Scanner};
use anyhow::{Result, bail};
use base64::Engine;
use serde::{
    Deserialize, Deserializer,
    de::{Error, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::HashSet, fmt};

// Reject duplicate keys at every nesting level before building the document.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut m = serde_json::Map::new();
                while let Some((k, v)) = a.next_entry::<String, Unique>()? {
                    if m.contains_key(&k) {
                        return Err(A::Error::custom("duplicate_key"));
                    }
                    m.insert(k, v.0);
                }
                Ok(Unique(Value::Object(m)))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut v = vec![];
                while let Some(x) = a.next_element::<Unique>()? {
                    v.push(x.0);
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_str<E: Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_bool<E: Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_unit<E: Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice::<Unique>(bytes)?.0)
}

pub struct Inspection {
    pub body: Value,
    pub rules: Vec<String>,
    pub changed: bool,
    pub unsafe_findings: bool,
}
pub async fn inspect(
    body: Value,
    scanner: &std::sync::Arc<Scanner>,
    attachments: &Attachments,
    scope: &str,
    sanitize: bool,
) -> Result<Inspection> {
    let mut result = Inspection {
        body,
        rules: vec![],
        changed: false,
        unsafe_findings: false,
    };
    let mut binaries = vec![];
    discover(&result.body, "", &mut binaries, 0)?;
    if binaries.len() > 16 {
        bail!("attachment_count_limit");
    }
    if binaries.iter().map(Vec::len).sum::<usize>() > 64 * 1024 * 1024 {
        bail!("attachment_total_limit");
    }
    for data in binaries {
        let outcome = attachments.inspect(&data, scope, sanitize).await?;
        result.unsafe_findings |= !outcome.rules.is_empty() && outcome.replacement.is_none();
        if let Some(replacement) = outcome.replacement {
            replace_attachment(&mut result.body, &data, &replacement)?;
            result.changed = true;
        }
        result.rules.extend(outcome.rules);
    }
    let permit = attachments.scan_slots.clone().acquire_owned().await?;
    let scanner = scanner.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        walk(
            &mut result.body,
            &scanner,
            &mut result.rules,
            &mut result.changed,
            &mut result.unsafe_findings,
            0,
        )?;
        Ok(result)
    })
    .await?
}
fn replace_attachment(v: &mut Value, original: &[u8], replacement: &[u8]) -> Result<()> {
    match v {
        Value::Object(m) => {
            for v in m.values_mut() {
                replace_attachment(v, original, replacement)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                replace_attachment(v, original, replacement)?;
            }
        }
        Value::String(s) => {
            let encoded = s
                .split_once(',')
                .filter(|_| s.starts_with("data:"))
                .map(|(_, b)| b)
                .unwrap_or(s);
            if base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .is_ok_and(|b| b == original)
            {
                let new = base64::engine::general_purpose::STANDARD.encode(replacement);
                *s = if s.starts_with("data:") {
                    crate::resolver::data_url(replacement)
                } else {
                    new
                };
            } else if let Ok(mut nested) = parse(s.as_bytes())
                && (nested.is_object() || nested.is_array())
            {
                replace_attachment(&mut nested, original, replacement)?;
                *s = serde_json::to_string(&nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn discover(v: &Value, key: &str, out: &mut Vec<Vec<u8>>, depth: usize) -> Result<()> {
    if depth > 64 {
        bail!("nesting_limit");
    }
    match v {
        Value::Object(m) => {
            if m.contains_key("file_id") || m.contains_key("file_url") {
                bail!("unresolved_attachment");
            }
            if key == "image_url"
                || m.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| matches!(t, "input_image" | "image_url"))
            {
                for k in ["url", "image_url"] {
                    if m.get(k)
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.starts_with("data:"))
                    {
                        bail!("remote_attachment_unsupported");
                    }
                }
            }
            if m.get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| matches!(t, "input_audio" | "audio" | "video" | "input_video"))
            {
                bail!("unsupported_attachment");
            }
            for (k, v) in m {
                discover(v, k, out, depth + 1)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                discover(v, key, out, depth + 1)?;
            }
        }
        Value::String(s) => {
            if (s.trim_start().starts_with('{') || s.trim_start().starts_with('['))
                && let Ok(inner) = parse(s.as_bytes())
            {
                discover(&inner, key, out, depth + 1)?;
            }
            let attachment = matches!(key, "file_data" | "image_url" | "image" | "data")
                || (key == "url" && s.starts_with("data:"));
            if s.starts_with("data:") {
                let (prefix, data) = s
                    .split_once(',')
                    .ok_or_else(|| anyhow::anyhow!("invalid_data_url"))?;
                if !prefix.ends_with(";base64") {
                    bail!("unsupported_data_encoding");
                }
                out.push(base64::engine::general_purpose::STANDARD.decode(data)?);
            } else if key == "file_data" {
                out.push(base64::engine::general_purpose::STANDARD.decode(s)?);
            } else if attachment && (s.starts_with("https:") || s.starts_with("http:")) {
                bail!("remote_attachment_unsupported");
            }
        }
        _ => {}
    }
    Ok(())
}
fn walk(
    v: &mut Value,
    s: &Scanner,
    rules: &mut Vec<String>,
    changed: &mut bool,
    unsafe_findings: &mut bool,
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        bail!("nesting_limit");
    }
    match v {
        Value::Object(m) => {
            for k in m.keys() {
                let findings = s.scan(k);
                if !findings.is_empty() {
                    *unsafe_findings = true;
                    rules.extend(findings.into_iter().map(|f| f.rule));
                }
            }
            for (k, v) in m {
                if matches!(k.as_str(), "file_data") {
                    continue;
                }
                if matches!(
                    k.as_str(),
                    "model"
                        | "role"
                        | "type"
                        | "id"
                        | "call_id"
                        | "name"
                        | "prompt_cache_key"
                        | "promptCacheKey"
                ) {
                    if let Some(text) = v.as_str() {
                        let findings = s.scan(text);
                        if !findings.is_empty() {
                            *unsafe_findings = true;
                            rules.extend(findings.into_iter().map(|f| f.rule));
                        }
                    }
                    if !v.is_string() {
                        walk(v, s, rules, changed, unsafe_findings, depth + 1)?;
                    }
                } else {
                    walk(v, s, rules, changed, unsafe_findings, depth + 1)?;
                }
            }
        }
        Value::Array(a) => {
            reconstruct_parts(a, s, rules, changed)?;
            for v in a {
                walk(v, s, rules, changed, unsafe_findings, depth + 1)?;
            }
        }
        Value::String(text) => {
            if text.starts_with("data:") {
                return Ok(());
            }
            let trim = text.trim();
            if (trim.starts_with('{') || trim.starts_with('['))
                && let Ok(mut inner) = parse(text.as_bytes())
            {
                let mut inner_changed = false;
                walk(
                    &mut inner,
                    s,
                    rules,
                    &mut inner_changed,
                    unsafe_findings,
                    depth + 1,
                )?;
                if inner_changed {
                    *text = serde_json::to_string(&inner)?;
                    *changed = true;
                }
                return Ok(());
            }
            let (redacted, found) = s.redact(text);
            if !found.is_empty() {
                *changed = true;
                *text = redacted;
                rules.extend(found.into_iter().map(|f| f.rule));
            }
        }
        _ => {}
    }
    if rules.len() > 10_000 {
        bail!("finding_limit");
    }
    Ok(())
}

/// @cc [owner:ghuntley,label:security] reconstructed-source-spans
/// Findings spanning ordered text parts MUST remove all contributing source
/// fragments. Non-text parts MUST NOT participate in reconstruction.
fn reconstruct_parts(
    parts: &mut [Value],
    scanner: &Scanner,
    rules: &mut Vec<String>,
    changed: &mut bool,
) -> Result<()> {
    let mut text = String::new();
    let mut map = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if let Some(value) = part.get("text").and_then(Value::as_str) {
            if !text.is_empty() {
                text.push('\n');
            }
            let start = text.len();
            text.push_str(value);
            map.push((index, start, text.len()));
        } else if !text.is_empty() {
            text.push_str("\n[CONTENT BOUNDARY]\n");
        }
    }
    if text.len() > 64 * 1024 * 1024 {
        bail!("reconstruction_limit");
    }
    let findings = scanner.scan(&text);
    for (index, start, end) in map {
        let mut spans: Vec<(usize, usize, String)> = Vec::new();
        for f in &findings {
            if f.start < end && f.end > start {
                let a = f.start.max(start) - start;
                let b = f.end.min(end) - start;
                if let Some(last) = spans.last_mut()
                    && a < last.1
                {
                    last.1 = last.1.max(b);
                    continue;
                }
                spans.push((a, b, f.rule.clone()));
            }
        }
        if let Some(value) = parts[index]
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            let mut value = value;
            for (a, b, rule) in spans.iter().rev() {
                value.replace_range(*a..*b, &format!("[REDACTED:{rule}]"));
            }
            if !spans.is_empty() {
                parts[index]["text"] = value.into();
                *changed = true;
                rules.extend(spans.into_iter().map(|s| s.2));
            }
        }
    }
    Ok(())
}

pub fn unique_rules(rules: &[String]) -> Vec<String> {
    let mut set: Vec<_> = rules
        .iter()
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    set.sort();
    set
}

#[cfg(test)]
mod properties {
    use super::*;
    use hegel::{TestCase, generators as gs};
    #[hegel::test]
    fn reconstructed_pem_removes_every_part_and_preserves_surroundings(tc: TestCase) {
        let split = tc.draw(gs::integers::<usize>().min_value(0).max_value(80));
        let scanner = Scanner::new(HashSet::new()).unwrap();
        let mut parts = vec![
            serde_json::json!({"type":"input_text","text":format!("before\n-----BEGIN PRIVATE KEY-----\n{}","A".repeat(split))}),
            serde_json::json!({"type":"input_text","text":format!("{}\n-----END PRIVATE KEY-----\nafter","A".repeat(80-split))}),
        ];
        let mut rules = Vec::new();
        let mut changed = false;
        reconstruct_parts(&mut parts, &scanner, &mut rules, &mut changed).unwrap();
        assert!(changed);
        assert!(!rules.is_empty());
        assert!(parts[0]["text"].as_str().unwrap().starts_with("before\n"));
        assert!(parts[1]["text"].as_str().unwrap().ends_with("\nafter"));
        assert!(
            !parts
                .iter()
                .any(|p| p["text"].as_str().unwrap().contains("PRIVATE KEY"))
        );
    }
}

/// @cc [owner:ghuntley,label:security] protocol-inspection-plan
/// Only the body owned by a classified plan MAY be inspected. Legacy plans MUST
/// use the existing acquisition and document walk without narrower coverage.
pub async fn inspect_plan(
    mut plan: crate::protocol::InspectionPlan,
    resolver: &crate::resolver::Resolver,
    scanner: &std::sync::Arc<Scanner>,
    attachments: &Attachments,
    scope: &str,
    sanitize: bool,
) -> Result<(Inspection, bool)> {
    use crate::protocol::Content;
    if matches!(plan.content, Content::Legacy) {
        let materialized = resolver
            .materialize(&mut plan.body)
            .await
            .map_err(|_| anyhow::anyhow!(PlanError::Acquisition))?;
        let mut inspection = inspect(plan.body, scanner, attachments, scope, sanitize).await?;
        inspection.changed |= materialized;
        return Ok((inspection, materialized));
    }
    // This bounds CPU scans, including scans that outlive a cancelled request.
    // Text-only requests share the budget even though they need no attachments.
    let permit = attachments.scan_slots.clone().acquire_owned().await?;
    let scanner = scanner.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        inspect_classified(plan, &scanner).map(|result| (result, false))
    })
    .await?
}

#[derive(Debug)]
pub enum PlanError {
    Unsupported,
    Acquisition,
}
impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "unsupported_content",
            Self::Acquisition => "attachment_resolution_failed",
        })
    }
}
impl std::error::Error for PlanError {}

pub fn inspect_classified(
    plan: crate::protocol::InspectionPlan,
    scanner: &Scanner,
) -> Result<Inspection> {
    let mut result = Inspection {
        body: Value::Null,
        rules: vec![],
        changed: false,
        unsafe_findings: false,
    };
    let mut body = plan.body;
    scan_content(&mut body, plan.content, scanner, &mut result, 0)?;
    result.body = body;
    Ok(result)
}

fn scan_control(
    value: &Value,
    scanner: &Scanner,
    result: &mut Inspection,
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        bail!("nesting_limit");
    }
    match value {
        Value::String(text) => scan_key(text, scanner, result),
        Value::Object(values) => {
            for (key, value) in values {
                scan_key(key, scanner, result);
                scan_control(value, scanner, result, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                scan_control(value, scanner, result, depth + 1)?;
            }
        }
        _ => {}
    }
    if result.rules.len() > 10_000 {
        bail!("finding_limit");
    }
    Ok(())
}
fn scan_key(text: &str, scanner: &Scanner, result: &mut Inspection) {
    let findings = scanner.scan(text);
    result.unsafe_findings |= !findings.is_empty();
    result
        .rules
        .extend(findings.into_iter().map(|finding| finding.rule));
}

/// @cc [owner:ghuntley,label:security] signed-group-integrity
/// Signed groups MUST remain unchanged. Any finding in a signed group MUST
/// prevent approval in enforcing modes; advisory MUST preserve original bytes.
/// Opaque content MUST reject in every mode.
fn scan_content(
    value: &mut Value,
    content: crate::protocol::Content,
    scanner: &Scanner,
    result: &mut Inspection,
    depth: usize,
) -> Result<()> {
    use crate::protocol::Content;
    if depth > 64 {
        bail!("nesting_limit");
    }
    match content {
        Content::EditableText => {
            let text = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("plan_mismatch"))?;
            let (replacement, findings) = scanner.redact(text);
            if !findings.is_empty() {
                *value = replacement.into();
                result.changed = true;
                result
                    .rules
                    .extend(findings.into_iter().map(|finding| finding.rule));
            }
        }
        Content::Structural => scan_control(value, scanner, result, depth)?,
        Content::SignedGroup => scan_control(value, scanner, result, depth)?,
        Content::JsonText(plan) => {
            let mut inner = plan.body;
            let mut nested = Inspection {
                body: Value::Null,
                rules: vec![],
                changed: false,
                unsafe_findings: false,
            };
            scan_content(&mut inner, plan.content, scanner, &mut nested, depth + 1)?;
            if nested.changed {
                *value = serde_json::to_string(&inner)?.into();
                result.changed = true;
            }
            result.rules.extend(nested.rules);
            result.unsafe_findings |= nested.unsafe_findings;
        }
        Content::Object(fields) => {
            let values = value
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("plan_mismatch"))?;
            anyhow::ensure!(values.len() == fields.len(), "plan_mismatch");
            for (key, content) in fields {
                scan_key(&key, scanner, result);
                let value = values
                    .get_mut(&key)
                    .ok_or_else(|| anyhow::anyhow!("plan_mismatch"))?;
                scan_content(value, content, scanner, result, depth + 1)?;
            }
        }
        Content::Array(parts) => scan_array(value, parts, scanner, result, depth, false)?,
        Content::TextBlocks(parts) => scan_array(value, parts, scanner, result, depth, true)?,
        Content::Unsupported | Content::OpaqueGroup | Content::Attachment => {
            return Err(PlanError::Unsupported.into());
        }
        Content::Legacy => bail!("legacy_plan_requires_acquisition"),
    }
    if result.rules.len() > 10_000 {
        bail!("finding_limit");
    }
    Ok(())
}
fn scan_array(
    value: &mut Value,
    parts: Vec<crate::protocol::Content>,
    scanner: &Scanner,
    result: &mut Inspection,
    depth: usize,
    reconstruct: bool,
) -> Result<()> {
    let values = value
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("plan_mismatch"))?;
    anyhow::ensure!(values.len() == parts.len(), "plan_mismatch");
    if reconstruct {
        reconstruct_native_parts(values, scanner, &mut result.rules, &mut result.changed)?;
    }
    for (value, content) in values.iter_mut().zip(parts) {
        scan_content(value, content, scanner, result, depth + 1)?;
    }
    Ok(())
}

// Anthropic text blocks can split a credential inside a fixed prefix. Scan their
// exact concatenation as well as the legacy line-oriented reconstruction. Build
// all spans from the original values before applying any replacement.
fn reconstruct_native_parts(
    parts: &mut [Value],
    scanner: &Scanner,
    rules: &mut Vec<String>,
    changed: &mut bool,
) -> Result<()> {
    for run in parts.chunk_by_mut(|a, b| {
        a.get("text").is_some_and(Value::is_string) && b.get("text").is_some_and(Value::is_string)
    }) {
        if run[0].get("text").is_some_and(Value::is_string) {
            reconstruct_native_run(run, scanner, rules, changed)?;
        }
    }
    Ok(())
}

fn reconstruct_native_run(
    parts: &mut [Value],
    scanner: &Scanner,
    rules: &mut Vec<String>,
    changed: &mut bool,
) -> Result<()> {
    let mut mapped: Vec<Vec<(usize, usize, String)>> = vec![vec![]; parts.len()];
    for separator in ["", "\n"] {
        let mut text = String::new();
        let mut sources = vec![];
        for (index, part) in parts.iter().enumerate() {
            if let Some(value) = part.get("text").and_then(Value::as_str) {
                if !text.is_empty() {
                    text.push_str(separator);
                }
                let start = text.len();
                text.push_str(value);
                sources.push((index, start, text.len()));
            }
        }
        if text.len() > 64 * 1024 * 1024 {
            bail!("reconstruction_limit");
        }
        for finding in scanner.scan(&text) {
            for &(index, start, end) in &sources {
                if finding.start < end && finding.end > start {
                    mapped[index].push((
                        finding.start.max(start) - start,
                        finding.end.min(end) - start,
                        finding.rule.clone(),
                    ));
                }
            }
        }
    }
    for (part, mut spans) in parts.iter_mut().zip(mapped) {
        spans.sort();
        spans.dedup();
        let mut merged: Vec<(usize, usize, String)> = vec![];
        for span in spans {
            if let Some(last) = merged.last_mut()
                && span.0 < last.1
            {
                last.1 = last.1.max(span.1);
            } else {
                merged.push(span);
            }
        }
        if let Some(Value::String(text)) = part.get_mut("text") {
            for (start, end, rule) in merged.into_iter().rev() {
                text.replace_range(start..end, &format!("[REDACTED:{rule}]"));
                rules.push(rule);
                *changed = true;
            }
        }
    }
    Ok(())
}
