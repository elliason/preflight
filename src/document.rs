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

#[derive(Clone, Copy)]
pub enum Format {
    Json,
    Responses,
}
impl Format {
    pub(crate) fn position(self) -> Position {
        match self {
            Self::Json => Position::Other,
            Self::Responses => Position::ResponsesRoot,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Position {
    ResponsesRoot,
    Input,
    Item,
    Other,
}
impl Position {
    pub(crate) fn field(self, key: &str) -> Self {
        if self == Self::ResponsesRoot && key == "input" {
            Self::Input
        } else {
            Self::Other
        }
    }
    pub(crate) fn element(self) -> Self {
        if self == Self::Input {
            Self::Item
        } else {
            Self::Other
        }
    }
    /// @cc [owner:ghuntley,label:security] responses-opaque-scope
    /// Only direct Responses input array items with type reasoning or compaction
    /// MAY treat their encrypted_content string as opaque state. Strings starting
    /// with data: or whose trimmed form starts with { or [ MUST retain ordinary
    /// handling. Nested objects and parsed JSON MUST NOT inherit this permission.
    pub(crate) fn opaque_item(self, map: &serde_json::Map<String, Value>) -> bool {
        self == Self::Item
            && matches!(
                map.get("type").and_then(Value::as_str),
                Some("reasoning" | "compaction")
            )
            && map
                .get("encrypted_content")
                .and_then(Value::as_str)
                .is_some_and(|text| {
                    !text.starts_with("data:")
                        && !text.trim_start().starts_with('{')
                        && !text.trim_start().starts_with('[')
                })
    }
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
    inspect_with_format(body, scanner, attachments, scope, sanitize, Format::Json).await
}
/// @cc [owner:ghuntley,label:security] responses-opaque-preservation
/// Scoped opaque strings MUST be scanned literally, never decoded or rewritten. Literal
/// findings or equality with an inspected attachment's base64 encoding when that
/// attachment has findings MUST set unsafe_findings. JSON- and data:-shaped values
/// MUST retain ordinary inspection, including decoding and attachment resolution.
pub async fn inspect_with_format(
    body: Value,
    scanner: &std::sync::Arc<Scanner>,
    attachments: &Attachments,
    scope: &str,
    sanitize: bool,
    format: Format,
) -> Result<Inspection> {
    let position = format.position();
    let mut result = Inspection {
        body,
        rules: vec![],
        changed: false,
        unsafe_findings: false,
    };
    let mut binaries = vec![];
    discover(&result.body, "", &mut binaries, 0, position)?;
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
            let opaque_match = replace_attachment(&mut result.body, &data, &replacement, position)?;
            result.unsafe_findings |= opaque_match && !outcome.rules.is_empty();
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
            position,
        )?;
        Ok(result)
    })
    .await?
}
/// @cc [owner:ghuntley,label:security] opaque-attachment-match
/// A scoped opaque string matching an attachment's base64 encoding MUST remain
/// unchanged and report the match so findings cannot be forwarded unredacted.
fn replace_attachment(
    v: &mut Value,
    original: &[u8],
    replacement: &[u8],
    position: Position,
) -> Result<bool> {
    let encoded_original = base64::engine::general_purpose::STANDARD.encode(original);
    replace_attachment_inner(v, original, replacement, position, &encoded_original)
}
fn replace_attachment_inner(
    v: &mut Value,
    original: &[u8],
    replacement: &[u8],
    position: Position,
    encoded_original: &str,
) -> Result<bool> {
    let mut opaque_match = false;
    match v {
        Value::Object(m) => {
            let opaque = position.opaque_item(m);
            for (key, v) in m {
                if opaque && key == "encrypted_content" && v.is_string() {
                    // Compare the known bytes' canonical encoding without
                    // decoding or rewriting the opaque value.
                    opaque_match |= v.as_str() == Some(encoded_original);
                    continue;
                }
                opaque_match |= replace_attachment_inner(
                    v,
                    original,
                    replacement,
                    position.field(key),
                    encoded_original,
                )?;
            }
        }
        Value::Array(a) => {
            for v in a {
                opaque_match |= replace_attachment_inner(
                    v,
                    original,
                    replacement,
                    position.element(),
                    encoded_original,
                )?;
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
                opaque_match |= replace_attachment_inner(
                    &mut nested,
                    original,
                    replacement,
                    Position::Other,
                    encoded_original,
                )?;
                *s = serde_json::to_string(&nested)?;
            }
        }
        _ => {}
    }
    Ok(opaque_match)
}
fn discover(
    v: &Value,
    key: &str,
    out: &mut Vec<Vec<u8>>,
    depth: usize,
    position: Position,
) -> Result<()> {
    if depth > 64 {
        bail!("nesting_limit");
    }
    match v {
        Value::Object(m) => {
            let opaque = position.opaque_item(m);
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
                if opaque && k == "encrypted_content" && v.is_string() {
                    continue;
                }
                discover(v, k, out, depth + 1, position.field(k))?;
            }
        }
        Value::Array(a) => {
            for v in a {
                discover(v, key, out, depth + 1, position.element())?;
            }
        }
        Value::String(s) => {
            if (s.trim_start().starts_with('{') || s.trim_start().starts_with('['))
                && let Ok(inner) = parse(s.as_bytes())
            {
                discover(&inner, key, out, depth + 1, Position::Other)?;
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
    position: Position,
) -> Result<()> {
    if depth > 64 {
        bail!("nesting_limit");
    }
    match v {
        Value::Object(m) => {
            let opaque = position.opaque_item(m);
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
                ) || (opaque && k == "encrypted_content" && v.is_string())
                {
                    if let Some(text) = v.as_str() {
                        let findings = s.scan(text);
                        if !findings.is_empty() {
                            *unsafe_findings = true;
                            rules.extend(findings.into_iter().map(|f| f.rule));
                        }
                    }
                    if !v.is_string() {
                        walk(
                            v,
                            s,
                            rules,
                            changed,
                            unsafe_findings,
                            depth + 1,
                            position.field(k),
                        )?;
                    }
                } else {
                    walk(
                        v,
                        s,
                        rules,
                        changed,
                        unsafe_findings,
                        depth + 1,
                        position.field(k),
                    )?;
                }
            }
        }
        Value::Array(a) => {
            reconstruct_parts(a, s, rules, changed)?;
            for v in a {
                walk(
                    v,
                    s,
                    rules,
                    changed,
                    unsafe_findings,
                    depth + 1,
                    position.element(),
                )?;
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
                    Position::Other,
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
    fn opaque_strings_are_not_decoded_or_rewritten(tc: TestCase) {
        let text = tc.draw(gs::text());
        // JSON/data shapes retain the old inspection path, covered by exact
        // fixtures. Here only literal scanner findings may contribute, and no
        // decoded interpretation or redaction may change the opaque value.
        if text.starts_with("data:")
            || text.trim_start().starts_with('{')
            || text.trim_start().starts_with('[')
        {
            return;
        }
        let kind = if tc.draw(gs::booleans()) {
            "reasoning"
        } else {
            "compaction"
        };
        let scanner = Scanner::new(HashSet::new()).unwrap();
        let expected = scanner.scan(&text);
        let original = serde_json::json!({"input":[{"type":kind,"encrypted_content":text}]});
        let mut body = original.clone();
        let mut rules = Vec::new();
        let mut changed = false;
        let mut unsafe_findings = false;
        walk(
            &mut body,
            &scanner,
            &mut rules,
            &mut changed,
            &mut unsafe_findings,
            0,
            Position::ResponsesRoot,
        )
        .unwrap();
        assert_eq!(body, original);
        assert!(!changed);
        assert_eq!(unsafe_findings, !expected.is_empty());
        assert_eq!(
            rules,
            expected
                .into_iter()
                .map(|finding| finding.rule)
                .collect::<Vec<_>>()
        );
    }

    #[hegel::test]
    fn opaque_attachment_matches_are_reported_without_rewriting(tc: TestCase) {
        let text = tc.draw(gs::text());
        let kind = if tc.draw(gs::booleans()) {
            "reasoning"
        } else {
            "compaction"
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
        let original = serde_json::json!({"input":[{"type":kind,"encrypted_content":encoded}]});
        let mut body = original.clone();
        assert!(
            replace_attachment(
                &mut body,
                text.as_bytes(),
                b"replacement",
                Position::ResponsesRoot
            )
            .unwrap()
        );
        assert_eq!(body, original);
    }

    #[hegel::test]
    fn opaque_findings_are_unsafe_and_never_rewritten(tc: TestCase) {
        let prefix = "λ ".repeat(tc.draw(gs::integers::<usize>().min_value(0).max_value(50)));
        let kind = if tc.draw(gs::booleans()) {
            "reasoning"
        } else {
            "compaction"
        };
        let token = format!("ghp_{}", "aB39".repeat(9));
        let scanner = Scanner::new(HashSet::new()).unwrap();
        let original = serde_json::json!({"input":[{"type":kind,"encrypted_content":format!("{prefix}{token} trailing")}]});
        let mut body = original.clone();
        let mut rules = Vec::new();
        let mut changed = false;
        let mut unsafe_findings = false;
        walk(
            &mut body,
            &scanner,
            &mut rules,
            &mut changed,
            &mut unsafe_findings,
            0,
            Position::ResponsesRoot,
        )
        .unwrap();
        assert_eq!(body, original);
        assert!(!changed);
        assert!(unsafe_findings);
        assert!(!rules.is_empty());
    }

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
