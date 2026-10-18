use base64::Engine;
use hegel::{TestCase, generators as gs};
use preflight::{anthropic, document, protocol::Adapter, scanner::Scanner};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::LazyLock};

static SCANNER: LazyLock<Scanner> = LazyLock::new(|| Scanner::new(HashSet::new()).unwrap());
fn jwt() -> String {
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        encoder.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        encoder.encode(br#"{"sub":"preflight-canary-not-a-secret"}"#),
        encoder.encode(b"fake-signature-never-valid")
    )
}
fn inspect(body: Value) -> anyhow::Result<document::Inspection> {
    document::inspect_classified(anthropic::classify(body)?, &SCANNER)
}
fn message(content: Value) -> Value {
    json!({"model":"claude-fixture","messages":[{"role":"user","content":content}]})
}

#[derive(serde::Deserialize)]
struct CapturedRequests {
    common: serde_json::Map<String, Value>,
    turns: Vec<serde_json::Map<String, Value>>,
}

#[test]
fn captured_claude_code_turns_are_completely_inspected_without_rewrites() {
    let capture: CapturedRequests =
        serde_json::from_str(include_str!("fixtures/claude-code-2.1.302.json")).unwrap();
    assert_eq!(capture.turns.len(), 5);
    for turn in capture.turns {
        let mut body = capture.common.clone();
        body.extend(turn);
        let original = serde_json::to_vec(&body).unwrap();
        let plan = Adapter::Messages.route().classify(&original).unwrap();
        let result = document::inspect_classified(plan, &SCANNER).unwrap();
        assert!(!result.changed);
        assert!(!result.unsafe_findings);
        assert!(result.rules.is_empty());
        assert_eq!(serde_json::to_vec(&result.body).unwrap(), original);
    }
}

#[test]
fn captured_controls_reject_findings_and_unclassified_extensions() {
    let controls = json!({
        "output_config":{"effort":"high"},
        "context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}
    });
    for (path, value) in [
        ("/output_config/effort", json!(jwt())),
        ("/output_config/format", json!({"type":"text","text":jwt()})),
        ("/context_management/edits/0/keep", json!(jwt())),
        ("/context_management/edits/0/type", json!("unsupported")),
        ("/context_management/edits/0/instructions", json!(jwt())),
    ] {
        let mut body = message(json!("hello"));
        body.as_object_mut()
            .unwrap()
            .extend(controls.as_object().unwrap().clone());
        let (parent, key) = path.rsplit_once('/').unwrap();
        body.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), value);
        assert!(inspect(body).is_err());
    }
}

#[test]
fn accepted_text_matrix_and_cache_control_are_covered() {
    let canary = jwt();
    let cache = json!({"type":"ephemeral","ttl":"1h"});
    let body = json!({"model":"claude-fixture", "system":[{"type":"text","text":canary,"cache_control":cache}],
        "tools":[{"name":"lookup","description":jwt(),"input_schema":{"type":"object","properties":{"value":{"type":"string","description":jwt()}},"required":["value"]},"cache_control":cache}],
        "messages":[{"role":"user","content":[{"type":"text","text":jwt(),"cache_control":cache},
        {"type":"tool_use","id":"tool_1","name":"lookup","input":{"name":jwt(),"file_id":jwt(),"data":jwt(),"nested":json!({"escaped":jwt()}).to_string()}},
        {"type":"tool_result","tool_use_id":"tool_1","content":jwt()},
        {"type":"tool_result","tool_use_id":"tool_1","content":[{"type":"text","text":jwt()}]}]}]});
    let result = inspect(body).unwrap();
    assert!(!result.unsafe_findings);
    assert!(!result.body.to_string().contains(&canary));
    assert_eq!(result.body["system"][0]["cache_control"], cache);
    assert_eq!(
        result.body["tools"][0]["input_schema"]["required"],
        json!(["value"])
    );
    assert_eq!(result.body["tools"][0]["cache_control"], cache);
    assert!(result.rules.iter().all(|rule| rule == "jwt"));
}
#[test]
fn structural_keys_constraints_and_signed_groups_are_never_rewritten() {
    let canary = jwt();
    for schema in [
        json!({"type":"object","properties":{canary.clone():{"type":"string"}}}),
        json!({"type":"string","enum":[canary]}),
        json!({"const":jwt()}),
        json!({"items":{"type":"string","enum":[jwt()]}}),
        json!({jwt():"value"}),
    ] {
        let mut body = message(json!("hello"));
        body["tools"] = json!([{"name":"lookup","input_schema":schema}]);
        let result = inspect(body.clone()).unwrap();
        assert!(result.unsafe_findings);
        assert_eq!(result.body, body);
    }
    for field in ["thinking", "signature"] {
        let mut block =
            json!({"type":"thinking","thinking":"visible","signature":"fixture-signature"});
        block[field] = jwt().into();
        let body = message(json!([block]));
        let result = inspect(body.clone()).unwrap();
        assert!(result.unsafe_findings);
        assert_eq!(result.body, body);
    }
}
#[test]
fn clean_nested_json_and_signed_blocks_preserve_values() {
    let body = message(json!([
        {"type":"thinking","thinking":"visible","signature":"fixture-signature"},
        {"type":"tool_use","id":"t","name":"lookup","input":{"nested":"{  \"path\": \"README.md\" }"}}
    ]));
    let result = inspect(body.clone()).unwrap();
    assert!(!result.changed);
    assert_eq!(result.body, body);
    let mut mixed = body.clone();
    mixed["messages"][0]["content"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"text","text":jwt()}));
    let result = inspect(mixed).unwrap();
    assert_eq!(
        result.body["messages"][0]["content"][0],
        body["messages"][0]["content"][0]
    );
}
#[test]
fn malformed_json_looking_tool_strings_are_scanned_as_text() {
    let canary = jwt();
    for nested in [
        format!("{{malformed {canary}"),
        format!(r#"{{"key":"{canary}","key":"duplicate"}}"#),
        format!("[ -f x ] && echo {canary}"),
        format!("{{ echo {canary}; }} > output"),
        "[REDACTED:jwt]".into(),
    ] {
        let body = message(
            json!([{"type":"tool_use","id":"t","name":"lookup","input":{"nested":nested}}]),
        );
        let result = inspect(body).unwrap();
        assert_eq!(
            result.body["messages"][0]["content"][0]["input"]["nested"],
            SCANNER.redact(&nested).0
        );
        assert!(!result.unsafe_findings);
    }
}
#[test]
fn unknown_fields_and_unsupported_blocks_fail_closed() {
    for content in [
        json!([{"type":"redacted_thinking","data":"opaque"}]),
        json!([{"type":"image","source":{}}]),
        json!([{"type":"document","source":{}}]),
        json!([{"type":"text","text":"hello","unknown":jwt()}]),
        json!([{"type":"tool_result","tool_use_id":"t","content":[{"type":"thinking","thinking":"visible","signature":"fake"}]}]),
    ] {
        assert!(inspect(message(content)).is_err());
    }
    let mut body = message(json!("hello"));
    body["unclassified"] = jwt().into();
    assert!(inspect(body).is_err());
}
#[test]
fn data_url_prefix_in_editable_text_is_not_an_attachment_exemption() {
    let result = inspect(message(json!(format!("data:literal {}", jwt())))).unwrap();
    assert_eq!(
        result.body["messages"][0]["content"],
        "data:literal [REDACTED:jwt]"
    );
}
#[test]
fn adjacent_text_parts_reconstruct_and_nontext_parts_bound_reconstruction() {
    let body = message(json!([{"type":"text","text":"-----BEGIN PRIVATE KEY-----"},
        {"type":"text","text":"synthetic-fixture\n-----END PRIVATE KEY-----"}]));
    let result = inspect(body).unwrap();
    assert!(result.changed);
    assert!(!result.body.to_string().contains("synthetic-fixture"));
    let separated = message(json!([
        {"type":"text","text":"-----BEGIN PRIVATE KEY-----synthetic"},
        {"type":"tool_use","id":"t","name":"lookup","input":{}},
        {"type":"text","text":"clean trailing text"}
    ]));
    let result = inspect(separated).unwrap();
    assert_eq!(
        result.body["messages"][0]["content"][2]["text"],
        "clean trailing text"
    );
}
#[test]
fn queries_are_exact_and_legacy_discard_is_explicit() {
    for adapter in [Adapter::Messages, Adapter::CountTokens] {
        let spec = adapter.route();
        for query in ["", "?beta=true"] {
            assert_eq!(
                spec.target(&format!("{}{query}", spec.path).parse().unwrap())
                    .unwrap(),
                format!("{}{query}", spec.path)
            );
        }
        for query in [
            "?",
            "?beta=false",
            "?beta=true&beta=true",
            "?other=true",
            "?beta=%74rue",
        ] {
            assert!(
                spec.target(&format!("{}{query}", spec.path).parse().unwrap())
                    .is_err()
            );
        }
    }
    for adapter in [Adapter::Responses, Adapter::ChatCompletions] {
        let spec = adapter.route();
        assert_eq!(
            spec.target(&format!("{}?legacy=discarded", spec.path).parse().unwrap())
                .unwrap(),
            spec.path
        );
    }
}
#[hegel::test]
fn editable_text_matches_scanner_and_preserves_structure(tc: TestCase) {
    let text = tc.draw(gs::text());
    let original = message(json!(text));
    let result = inspect(original).unwrap();
    assert_eq!(
        result.body["messages"][0]["content"],
        SCANNER.redact(&text).0
    );
    assert_eq!(result.body["model"], "claude-fixture");
    assert_eq!(result.body["messages"][0]["role"], "user");
    assert!(!inspect(result.body).unwrap().changed);
}
#[hegel::test]
fn arbitrary_signed_text_is_preserved_and_findings_always_protect_group(tc: TestCase) {
    let text = tc.draw(gs::text());
    let signature = tc.draw(gs::text());
    let body = message(json!([{"type":"thinking","thinking":text,"signature":signature}]));
    let result = inspect(body.clone()).unwrap();
    assert_eq!(result.body, body);
    assert!(!result.changed);
    assert_eq!(
        result.unsafe_findings,
        !SCANNER.scan(&text).is_empty() || !SCANNER.scan(&signature).is_empty()
    );
}
#[hegel::test]
fn unknown_content_types_never_become_approved(tc: TestCase) {
    let kind = format!("unsupported_{}", tc.draw(gs::text()));
    assert!(inspect(message(json!([{"type":kind,"text":"hello"}]))).is_err());
}
#[hegel::test]
fn tool_json_values_are_editable_but_keys_are_scan_only(tc: TestCase) {
    let key = tc.draw(gs::text());
    let canary = jwt();
    let body =
        message(json!([{"type":"tool_use","id":"t","name":"lookup","input":{key.clone():canary}}]));
    let result = inspect(body).unwrap();
    assert_eq!(
        result.body["messages"][0]["content"][0]["input"][&key],
        "[REDACTED:jwt]"
    );
    assert_eq!(result.unsafe_findings, !SCANNER.scan(&key).is_empty());
}

#[hegel::test]
fn arbitrary_tool_input_strings_do_not_fail_json_parsing(tc: TestCase) {
    let text = tc.draw(gs::text());
    for prefix in ["", "{", "["] {
        let input = format!("{prefix}{text}");
        let body = message(json!([
            {"type":"tool_use","id":"t","name":"lookup","input":{"value":input}}
        ]));
        assert!(inspect(body).is_ok());
    }
}

#[hegel::test]
fn every_split_of_a_jwt_across_adjacent_text_blocks_is_removed(tc: TestCase) {
    let canary = jwt();
    let split = tc.draw(gs::integers::<usize>().min_value(0).max_value(canary.len()));
    let body = message(
        json!([{"type":"text","text":&canary[..split]}, {"type":"text","text":&canary[split..]}]),
    );
    let result = inspect(body).unwrap();
    let text = format!(
        "{}{}",
        result.body["messages"][0]["content"][0]["text"]
            .as_str()
            .unwrap(),
        result.body["messages"][0]["content"][1]["text"]
            .as_str()
            .unwrap()
    );
    assert!(!text.contains(&canary));
    assert!(text == "[REDACTED:jwt]" || text == "[REDACTED:jwt][REDACTED:jwt]");
}
