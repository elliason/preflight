use super::*;
use axum::{body::Bytes, http::Uri};
use base64::Engine;
use serde_json::{Value, json};

fn jwt() -> String {
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        encoder.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        encoder.encode(br#"{"sub":"preflight-canary-not-a-secret"}"#),
        encoder.encode(b"fake-signature-never-valid")
    )
}
fn app(dir: &std::path::Path, upstream: String, mode: Mode) -> App {
    let scanner = Arc::new(Scanner::new(HashSet::new()).unwrap());
    // Text-only HTTP tests exercise the real route/approval/forwarding pipeline.
    // Sandbox remains enabled; no worker is needed for this content matrix.
    let attachments = Attachments::new(
        scanner.clone(),
        Arc::new(Mutex::new(Cache::open(dir).unwrap())),
        "preflight-worker".into(),
        true,
    );
    App {
        config: Config {
            upstream,
            mode,
            ..Config::default()
        },
        scanner,
        attachments,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        client_key: Some("local-fixture-key".into()),
        upstream_key: Some("upstream-fixture-key".into()),
        admission: Arc::new(tokio::sync::Semaphore::new(16)),
    }
}
#[derive(Clone)]
struct Captured {
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}
const SSE: &[u8] = b"event: message_start\ndata: {\"type\":\"message_start\"}\n\nevent: future_event\ndata: {\"unknown\":true}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

async fn anthropic_path(adapter: Adapter, upstream_auth: AnthropicUpstreamAuth) {
    let response_bytes: &'static [u8] = if adapter == Adapter::Messages {
        SSE
    } else {
        br#"{"input_tokens":16}"#
    };
    let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
    let seen = captured.clone();
    let upstream = Router::new().route(
        adapter.route().path,
        post(move |uri: Uri, headers: HeaderMap, body: Bytes| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(Captured { uri, headers, body });
                let chunks = futures::stream::iter(
                    response_bytes
                        .chunks(13)
                        .map(|part| Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(part)))
                        .collect::<Vec<_>>(),
                );
                (
                    [(
                        "content-type",
                        if adapter == Adapter::Messages {
                            "text/event-stream"
                        } else {
                            "application/json"
                        },
                    )],
                    Body::from_stream(chunks),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = app(
        temp.path(),
        format!("http://{upstream_address}"),
        Mode::Redact,
    );
    runtime.config.anthropic_upstream_auth = upstream_auth;
    let live = Arc::new(Live {
        current: RwLock::new(Arc::new(runtime)),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = router(live.clone());
    let proxy = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{address}{}", adapter.route().path);
    for (query, auth) in [("", "authorization"), ("?beta=true", "x-api-key")] {
        let value = if auth == "authorization" {
            "Bearer local-fixture-key"
        } else {
            "local-fixture-key"
        };
        let canary = jwt();
        let mut body = json!({"model":"claude-fixture",
            "messages":[{"role":"user","content":canary},
                {"role":"assistant","content":[{"type":"tool_use","id":"tool_1","name":"lookup","input":{"nested":json!({"value":jwt()}).to_string()}}]},
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_1","content":[{"type":"text","text":jwt()}]}]}]});
        if adapter == Adapter::Messages {
            body["max_tokens"] = json!(32);
            body["stream"] = json!(true);
        }
        let response = client
            .post(format!("{url}{query}"))
            .header(auth, value)
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta", "fixture-beta-2026-10-18")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.bytes().await.unwrap().as_ref(), response_bytes);
        let sent = captured.lock().unwrap().last().unwrap().clone();
        assert_eq!(sent.uri.path(), adapter.route().path);
        assert_eq!(
            sent.uri.query(),
            if query.is_empty() {
                None
            } else {
                Some("beta=true")
            }
        );
        match upstream_auth {
            AnthropicUpstreamAuth::XApiKey => {
                assert_eq!(sent.headers["x-api-key"], "upstream-fixture-key");
                assert!(!sent.headers.contains_key("authorization"));
            }
            AnthropicUpstreamAuth::Bearer => {
                assert_eq!(sent.headers["authorization"], "Bearer upstream-fixture-key");
                assert!(!sent.headers.contains_key("x-api-key"));
            }
        }
        assert_eq!(sent.headers["anthropic-version"], "2023-06-01");
        assert_eq!(sent.headers["anthropic-beta"], "fixture-beta-2026-10-18");
        let forwarded = std::str::from_utf8(&sent.body).unwrap();
        assert!(!forwarded.contains(&canary));
        assert_eq!(forwarded.matches("[REDACTED:jwt]").count(), 3);
    }
    let clean = br#"{ "model":"claude-fixture", "messages":[{"role":"user","content":"hello"}] }"#;
    let response = client
        .post(&url)
        .header("x-api-key", "local-fixture-key")
        .body(clean.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        captured.lock().unwrap().last().unwrap().body.as_ref(),
        clean
    );
    let before = captured.lock().unwrap().len();
    let fixture = json!({"model":"claude-fixture","messages":[{"role":"user","content":"hello"}]})
        .to_string();
    let blocked = [
        (json!({"model":"claude-fixture","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"fake"}}]}]}).to_string(), Some("local-fixture-key"), "", 400),
        (json!({"model":"claude-fixture","messages":[{"role":"assistant","content":[{"type":"thinking","thinking":jwt(),"signature":"signed-fixture"}]}]}).to_string(), Some("local-fixture-key"), "", 400),
        (fixture.clone(), Some("wrong-fixture-key"), "", 401),
        (fixture.clone(), None, "", 401),
        ("{malformed".into(), Some("local-fixture-key"), "", 400),
        (r#"{"model":"a","model":"b","messages":[]}"#.into(), Some("local-fixture-key"), "", 400),
        (fixture.clone(), Some("local-fixture-key"), "?beta=false", 400),
        (fixture.clone(), Some("local-fixture-key"), "?beta=true&unknown=1", 400),
    ];
    for (body, key, query, status) in blocked {
        let request = client.post(format!("{url}{query}")).body(body);
        let request = if let Some(key) = key {
            request.header("x-api-key", key)
        } else {
            request
        };
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["x-should-retry"], "false");
        let error: Value = response.json().await.unwrap();
        assert_eq!(error["type"], "error");
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("preflight:")
        );
        assert!(!error.to_string().contains(&jwt()));
        assert_eq!(captured.lock().unwrap().len(), before);
    }
    for headers in [
        [
            ("x-api-key", "local-fixture-key"),
            ("authorization", "Bearer conflicting-fixture"),
        ],
        [
            ("x-api-key", "local-fixture-key"),
            ("anthropic-beta", "invalid/beta"),
        ],
        [
            ("x-api-key", "local-fixture-key"),
            ("anthropic-version", "invalid-version"),
        ],
        [
            ("x-api-key", "local-fixture-key"),
            ("x-api-key", "local-fixture-key"),
        ],
    ] {
        let mut map = HeaderMap::new();
        for (key, value) in headers {
            map.append(key, value.parse().unwrap());
        }
        let response = client
            .post(&url)
            .headers(map)
            .body(fixture.clone())
            .send()
            .await
            .unwrap();
        assert!(response.status().is_client_error());
        let error: Value = response.json().await.unwrap();
        assert_eq!(error["type"], "error");
        assert_eq!(captured.lock().unwrap().len(), before);
    }
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.json::<Value>().await.unwrap()["type"], "error");
    assert_eq!(captured.lock().unwrap().len(), before);

    let advisory_temp = tempfile::tempdir().unwrap();
    *live.current.write().unwrap() = Arc::new(app(
        advisory_temp.path(),
        format!("http://{upstream_address}"),
        Mode::Advisory,
    ));
    let signed = format!(
        "{{ \"model\":\"claude-fixture\", \"messages\":[{{\"role\":\"assistant\",\"content\":[{{\"type\":\"thinking\",\"thinking\":\"{}\",\"signature\":\"fake-signature\"}}]}}] }}",
        jwt()
    );
    let response = client
        .post(&url)
        .header("authorization", "bEaReR local-fixture-key")
        .body(signed.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), response_bytes);
    assert_eq!(captured.lock().unwrap().len(), before + 1);
    assert_eq!(
        captured.lock().unwrap().last().unwrap().body.as_ref(),
        signed.as_bytes()
    );
    proxy.abort();
    upstream_task.abort();
}
#[tokio::test]
async fn messages_inspect_every_input_before_streaming_or_reject_without_forwarding() {
    anthropic_path(Adapter::Messages, AnthropicUpstreamAuth::XApiKey).await;
}
#[tokio::test]
async fn count_tokens_inspects_every_input_before_counting_or_rejects_without_forwarding() {
    anthropic_path(Adapter::CountTokens, AnthropicUpstreamAuth::XApiKey).await;
}

#[hegel::test]
fn supported_messages_cannot_approve_a_canary_in_enforcing_modes(tc: hegel::TestCase) {
    use hegel::generators as gs;
    static SCANNER: std::sync::LazyLock<Scanner> =
        std::sync::LazyLock::new(|| Scanner::new(HashSet::new()).unwrap());
    let mut body = json!({
        "model":"claude-fixture", "max_tokens":32,
        "system":[{"type":"text","text":"fake system","cache_control":{"type":"ephemeral","ttl":"5m"}}],
        "messages":[
            {"role":"user","content":[{"type":"text","text":"fake user"}]},
            {"role":"assistant","content":[{"type":"tool_use","id":"tool_1","name":"lookup","input":{"value":"fake input"}}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_1","content":[{"type":"text","text":"fake output"}]}]},
            {"role":"assistant","content":[{"type":"thinking","thinking":"fake thought","signature":"fake-signature"}]}
        ],
        "tools":[{"name":"lookup","description":"fake description","input_schema":{
            "type":"object", "title":"fake title", "description":"fake schema",
            "properties":{"value":{"type":"string","description":"fake property","enum":["fake enum"],"const":"fake const"}},
            "required":["value"]
        },"cache_control":{"type":"ephemeral","scope":"fixture"}}],
        "metadata":{"user_id":"fake user"}, "stop_sequences":["fake stop"],
        "tool_choice":{"type":"tool","name":"lookup"}
    });
    // Include editable strings, scan-only controls, nested schema strings,
    // signed values, and keys. All generated documents remain classifiable.
    let leaves = [
        "/model",
        "/system/0/text",
        "/system/0/cache_control/ttl",
        "/messages/0/content/0/text",
        "/messages/1/content/0/id",
        "/messages/1/content/0/name",
        "/messages/1/content/0/input/value",
        "/messages/2/content/0/tool_use_id",
        "/messages/2/content/0/content/0/text",
        "/messages/3/content/0/thinking",
        "/messages/3/content/0/signature",
        "/tools/0/name",
        "/tools/0/description",
        "/tools/0/input_schema/title",
        "/tools/0/input_schema/description",
        "/tools/0/input_schema/properties/value/description",
        "/tools/0/input_schema/properties/value/enum/0",
        "/tools/0/input_schema/properties/value/const",
        "/tools/0/input_schema/required/0",
        "/tools/0/cache_control/scope",
        "/metadata/user_id",
        "/stop_sequences/0",
        "/tool_choice/name",
    ];
    let leaf = tc.draw(
        gs::integers::<usize>()
            .min_value(0)
            .max_value(leaves.len() + 1),
    );
    let canary = jwt();
    if leaf < leaves.len() {
        *body.pointer_mut(leaves[leaf]).unwrap() = json!(format!(
            "{} {canary} {}",
            tc.draw(gs::text()),
            tc.draw(gs::text())
        ));
    } else if leaf == leaves.len() {
        body["messages"][1]["content"][0]["input"][&canary] = json!("fake input");
    } else {
        body["tools"][0]["input_schema"]["properties"][&canary] = json!({"type":"string"});
    }
    // Exercise object/array nesting independently from the injection location.
    let input = &mut body["messages"][1]["content"][0]["input"]["value"];
    for _ in 0..tc.draw(gs::integers::<usize>().min_value(0).max_value(8)) {
        *input = json!({"nested":[input.take()]});
    }
    if tc.draw(gs::integers::<u8>().min_value(0).max_value(1)) == 1 {
        let text = body["messages"][0]["content"][0]["text"].take();
        body["messages"][0]["content"] = text;
    }
    let original = serde_json::to_vec(&body).unwrap();
    for mode in [Mode::Redact, Mode::NoGo, Mode::Advisory] {
        let plan = Adapter::Messages.route().classify(&original).unwrap();
        let inspection = document::inspect_classified(plan, &SCANNER).unwrap();
        assert!(!inspection.rules.is_empty());
        match approve(&original, inspection, mode, &[], Family::Anthropic) {
            Ok(approved) if mode == Mode::Advisory => assert_eq!(approved.bytes, original),
            Ok(approved) => {
                assert!(mode == Mode::Redact);
                assert!(
                    !std::str::from_utf8(&approved.bytes)
                        .unwrap()
                        .contains(&canary)
                );
            }
            Err(_) => assert!(mode != Mode::Advisory),
        }
    }
}

#[test]
fn native_auth_preserves_one_upstream_credential_and_requires_local_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = app(temp.path(), "http://127.0.0.1:1".into(), Mode::Redact);
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer local-fixture-key".parse().unwrap());
    headers.insert("x-api-key", "local-fixture-key".parse().unwrap());
    assert!(anthropic_authorized(&runtime, &headers));
    assert_eq!(
        anthropic_upstream_auth(&runtime, &headers)
            .unwrap()
            .unwrap(),
        ("x-api-key", "upstream-fixture-key".parse().unwrap())
    );
    runtime.upstream_key = None;
    assert!(anthropic_upstream_auth(&runtime, &headers).is_err());
    runtime.client_key = None;
    assert_eq!(
        anthropic_upstream_auth(&runtime, &headers)
            .unwrap()
            .unwrap()
            .0,
        "x-api-key"
    );
    headers.remove("x-api-key");
    assert_eq!(
        anthropic_upstream_auth(&runtime, &headers)
            .unwrap()
            .unwrap()
            .0,
        "authorization"
    );
}

#[tokio::test]
async fn native_errors_use_timeout_type_and_disable_deterministic_retries() {
    for (status, code, expected, kind, retry) in [
        (
            StatusCode::REQUEST_TIMEOUT,
            "inspection_deadline",
            504,
            "timeout_error",
            None,
        ),
        (
            StatusCode::BAD_REQUEST,
            "unsupported_content",
            400,
            "invalid_request_error",
            Some("false"),
        ),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_limit",
            413,
            "request_too_large",
            Some("false"),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "inspection_capacity",
            503,
            "overloaded_error",
            None,
        ),
    ] {
        let response = protocol_error(Family::Anthropic, status, code);
        assert_eq!(response.status(), expected);
        assert_eq!(
            response
                .headers()
                .get("x-should-retry")
                .map(|v| v.to_str().unwrap()),
            retry
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["type"], kind);
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("preflight: ")
        );
    }
}

#[test]
fn native_beta_list_allows_thirty_two_entries() {
    let mut headers = HeaderMap::new();
    for count in [1, 32, 33] {
        let value = std::iter::repeat_n("fixture-beta", count)
            .collect::<Vec<_>>()
            .join(",");
        headers.insert("anthropic-beta", value.parse().unwrap());
        assert_eq!(anthropic_headers_valid(&headers), count <= 32);
    }
}

#[tokio::test]
async fn native_policy_errors_are_static_and_advisory_keeps_editable_originals() {
    let scanner = Scanner::new(HashSet::new()).unwrap();
    let original = serde_json::to_vec(
        &json!({"model":"fixture","messages":[{"role":"user","content":jwt()}]}),
    )
    .unwrap();
    for mode in [Mode::NoGo, Mode::Advisory] {
        let plan = Adapter::Messages.route().classify(&original).unwrap();
        let inspection = document::inspect_classified(plan, &scanner).unwrap();
        let approved = approve(&original, inspection, mode, &[], Family::Anthropic);
        if mode == Mode::Advisory {
            assert_eq!(approved.unwrap().bytes, original);
        } else {
            let response = match approved {
                Err(response) => response,
                Ok(_) => panic!("no-go approved finding"),
            };
            assert_eq!(response.status(), 400);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let error: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(error["type"], "error");
            assert_eq!(error["error"]["type"], "invalid_request_error");
            assert!(!std::str::from_utf8(&bytes).unwrap().contains(&jwt()));
        }
    }
}

#[tokio::test]
async fn matrix_rejections_never_forward_in_any_mode_or_native_route() {
    let matrix: Value =
        serde_json::from_str(include_str!("../tests/fixtures/anthropic-content.json")).unwrap();
    let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
    let seen = captured.clone();
    let upstream = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let seen = seen.clone();
        async move {
            seen.lock().unwrap().push(Captured { uri, headers, body });
            axum::Json(json!({"ok":true}))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    for mode in [Mode::Redact, Mode::NoGo, Mode::Advisory] {
        let temp = tempfile::tempdir().unwrap();
        let live = Arc::new(Live {
            current: RwLock::new(Arc::new(app(
                temp.path(),
                format!("http://{upstream_address}"),
                mode,
            ))),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move { axum::serve(listener, router(live)).await.unwrap() });
        let client = reqwest::Client::new();
        for adapter in [Adapter::Messages, Adapter::CountTokens] {
            let url = format!("http://{address}{}", adapter.route().path);
            for block in matrix["accepted"].as_array().unwrap() {
                let body =
                    json!({"model":"fixture","messages":[{"role":"user","content":[block]}]});
                let original = serde_json::to_vec(&body).unwrap();
                let response = client
                    .post(&url)
                    .header("x-api-key", "local-fixture-key")
                    .body(original.clone())
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200, "{block}");
                assert_eq!(
                    captured.lock().unwrap().last().unwrap().body.as_ref(),
                    original
                );
            }
            let canary = jwt();
            for block in [
                json!({"type":"document","source":{"type":"content","content":[{"type":"text","text":&canary[..1]},{"type":"text","text":&canary[1..]}]}}),
                json!({"type":"text_editor_code_execution_tool_result","tool_use_id":"t","content":{"type":"text_editor_code_execution_str_replace_result","lines":[&canary[..1], &canary[1..]]}}),
            ] {
                let before = captured.lock().unwrap().len();
                let body =
                    json!({"model":"fixture","messages":[{"role":"user","content":[block]}]});
                let response = client
                    .post(&url)
                    .header("x-api-key", "local-fixture-key")
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                if mode == Mode::NoGo {
                    assert_eq!(response.status(), 400);
                    assert_eq!(captured.lock().unwrap().len(), before);
                } else {
                    assert_eq!(response.status(), 200);
                    let sent: Value =
                        serde_json::from_slice(&captured.lock().unwrap().last().unwrap().body)
                            .unwrap();
                    if mode == Mode::Advisory {
                        assert_eq!(sent, body);
                    } else {
                        assert!(!sent.to_string().contains(&canary[1..]));
                    }
                }
            }
            let mut rejected = matrix["rejected"].as_array().unwrap().clone();
            for block in matrix["accepted"].as_array().unwrap() {
                let mut block = block.clone();
                block["future_field"] = json!("visible");
                rejected.push(json!({"block":block,"reason":"unsupported"}));
            }
            for (source, reason) in [
                (
                    json!({"type":"base64","media_type":"image/png","data":"!"}),
                    "base64",
                ),
                (
                    json!({"type":"base64","media_type":"image/png","data":"dGV4dA=="}),
                    "media_type",
                ),
                (json!({"type":"url","url":"http://127.0.0.1/"}), "inspected"),
                (
                    json!({"type":"url","url":"https://127.0.0.1/"}),
                    "inspected",
                ),
                (
                    json!({"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}),
                    "inspected",
                ),
            ] {
                rejected.push(json!({"block":{"type":"image","source":source},"reason":reason}));
            }
            for fixture in rejected {
                let before = captured.lock().unwrap().len();
                let body = json!({"model":"fixture","messages":[{"role":"user","content":[{"type":"text","text":"visible"},fixture["block"]]}]});
                let response = client
                    .post(&url)
                    .header("x-api-key", "local-fixture-key")
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                assert!(response.status().is_client_error(), "{fixture}");
                let error: Value = response.json().await.unwrap();
                assert_eq!(error["type"], "error");
                assert!(
                    error["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains(fixture["reason"].as_str().unwrap()),
                    "{error} {fixture}"
                );
                assert_eq!(captured.lock().unwrap().len(), before);
            }
        }
        proxy.abort();
    }
    upstream_task.abort();
}

#[hegel::test]
fn matrix_approved_bytes_never_contain_an_injected_leaf_canary(tc: hegel::TestCase) {
    use hegel::generators as gs;
    fn paths(value: &Value, path: String, out: &mut Vec<String>) {
        match value {
            Value::Object(values) => {
                for (key, value) in values {
                    paths(value, format!("{path}/{key}"), out);
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    paths(value, format!("{path}/{index}"), out);
                }
            }
            _ => out.push(path),
        }
    }
    static SCANNER: std::sync::LazyLock<Scanner> =
        std::sync::LazyLock::new(|| Scanner::new(HashSet::new()).unwrap());
    let matrix: Value =
        serde_json::from_str(include_str!("../tests/fixtures/anthropic-content.json")).unwrap();
    fn needs_acquisition(value: &Value) -> bool {
        match value {
            Value::Object(fields) => {
                fields
                    .get("source")
                    .is_some_and(|source| matches!(source["type"].as_str(), Some("base64" | "url")))
                    || fields.values().any(needs_acquisition)
            }
            Value::Array(values) => values.iter().any(needs_acquisition),
            _ => false,
        }
    }
    let accepted: Vec<_> = matrix["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|block| !needs_acquisition(block))
        .collect();
    assert!(!accepted.is_empty());
    let mut body = json!({"model":"fixture","messages":[{"role":"user","content":[accepted[tc.draw(gs::integers::<usize>().min_value(0).max_value(accepted.len()-1))]]}]});
    let mut leaves = vec![];
    paths(&body, String::new(), &mut leaves);
    *body
        .pointer_mut(
            &leaves[tc.draw(
                gs::integers::<usize>()
                    .min_value(0)
                    .max_value(leaves.len() - 1),
            )],
        )
        .unwrap() = json!(jwt());
    let original = serde_json::to_vec(&body).unwrap();
    for adapter in [Adapter::Messages, Adapter::CountTokens] {
        for mode in [Mode::Redact, Mode::NoGo] {
            // The matrix contains text-only sources. Inspection failure for a
            // classified fixture is a test failure, never an implicit rejection.
            let plan = match adapter.route().classify(&original) {
                Ok(plan) => plan,
                Err(_) => continue, // Explicitly rejected before approval.
            };
            let inspection = document::inspect_classified(plan, &SCANNER)
                .expect("classified text fixture must complete inspection");
            match approve(&original, inspection, mode, &[], Family::Anthropic) {
                Err(_) => {} // Explicitly rejected by enforcing policy.
                Ok(approved) => {
                    assert!(!String::from_utf8(approved.bytes).unwrap().contains(&jwt()))
                }
            }
        }
    }
}

#[tokio::test]
async fn native_messages_and_counts_support_bearer_upstream_auth() {
    anthropic_path(Adapter::Messages, AnthropicUpstreamAuth::Bearer).await;
    anthropic_path(Adapter::CountTokens, AnthropicUpstreamAuth::Bearer).await;
}

#[test]
fn upstream_auth_form_is_validated_at_configuration_load() {
    for (value, expected) in [
        ("x-api-key", AnthropicUpstreamAuth::XApiKey),
        ("bearer", AnthropicUpstreamAuth::Bearer),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fixture.toml");
        std::fs::write(&path, format!("anthropic_upstream_auth = \"{value}\"\n")).unwrap();
        assert_eq!(load(Some(path)).unwrap().anthropic_upstream_auth, expected);
    }
    for value in ["basic", "Bearer", "", "x_api_key"] {
        assert!(
            toml::from_str::<Config>(&format!("anthropic_upstream_auth = \"{value}\"")).is_err()
        );
    }
    assert_eq!(
        toml::from_str::<Config>("")
            .unwrap()
            .anthropic_upstream_auth,
        AnthropicUpstreamAuth::XApiKey
    );
}

#[tokio::test]
async fn native_discovery_validates_queries_and_unknown_message_routes_are_native_errors() {
    let captured = Arc::new(Mutex::new(Vec::<Captured>::new()));
    let seen = captured.clone();
    let upstream = Router::new().route(
        "/v1/models",
        get(move |uri: Uri, headers: HeaderMap| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(Captured {
                    uri,
                    headers,
                    body: Bytes::new(),
                });
                ([("content-type", "application/json")], "{ \"data\": [] }")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let client = reqwest::Client::new();
    for auth in [
        AnthropicUpstreamAuth::XApiKey,
        AnthropicUpstreamAuth::Bearer,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut runtime = app(
            temp.path(),
            format!("http://{upstream_address}"),
            Mode::Redact,
        );
        runtime.config.anthropic_upstream_auth = auth;
        let live = Arc::new(Live {
            current: RwLock::new(Arc::new(runtime)),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move { axum::serve(listener, router(live)).await.unwrap() });
        for query in [
            "",
            "?limit=1000",
            "?after_id=fixture&limit=1&beta=true",
            "?before_id=fixture",
        ] {
            for (header, value) in [
                ("x-api-key", "local-fixture-key"),
                ("authorization", "Bearer local-fixture-key"),
            ] {
                let response = client
                    .get(format!("http://{address}/v1/models{query}"))
                    .header(header, value)
                    .header("anthropic-version", "2023-06-01")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                assert_eq!(response.text().await.unwrap(), "{ \"data\": [] }");
                let sent = captured.lock().unwrap().last().unwrap().clone();
                assert_eq!(sent.uri.to_string(), format!("/v1/models{query}"));
                assert_eq!(sent.headers["anthropic-version"], "2023-06-01");
                match auth {
                    AnthropicUpstreamAuth::XApiKey => {
                        assert_eq!(sent.headers["x-api-key"], "upstream-fixture-key");
                        assert!(!sent.headers.contains_key("authorization"));
                    }
                    AnthropicUpstreamAuth::Bearer => {
                        assert_eq!(sent.headers["authorization"], "Bearer upstream-fixture-key");
                        assert!(!sent.headers.contains_key("x-api-key"));
                    }
                }
            }
        }
        // Native x-api-key selects native behavior even without a version header.
        let response = client
            .get(format!("http://{address}/v1/models?limit=2"))
            .header("x-api-key", "local-fixture-key")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            captured.lock().unwrap().last().unwrap().uri.query(),
            Some("limit=2")
        );
        // Ordinary bearer-only discovery preserves legacy query discard and upstream bearer.
        let response = client
            .get(format!("http://{address}/v1/models?legacy=discarded"))
            .header("authorization", "Bearer local-fixture-key")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let sent = captured.lock().unwrap().last().unwrap().clone();
        assert!(sent.uri.query().is_none());
        assert_eq!(sent.headers["authorization"], "Bearer upstream-fixture-key");
        let before = captured.lock().unwrap().len();
        for query in [
            "?limit=0",
            "?limit=1001",
            "?limit=1&limit=2",
            "?limit=%31",
            "?unknown=1",
            "?before_id=a&after_id=b",
            "?after_id=",
            "?beta=false",
        ] {
            let response = client
                .get(format!("http://{address}/v1/models{query}"))
                .header("x-api-key", "local-fixture-key")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 400);
            assert_eq!(
                response.json::<Value>().await.unwrap()["error"]["type"],
                "invalid_request_error"
            );
            assert_eq!(captured.lock().unwrap().len(), before);
        }
        let response = client
            .get(format!("http://{address}/v1/models"))
            .header("anthropic-version", "2023-06-01")
            .header("x-api-key", "wrong-fixture-key")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        assert_eq!(captured.lock().unwrap().len(), before);
        for path in [
            "/v1/messages/cache_touch",
            "/v1/messages/batches",
            "/v1/messages/unknown",
        ] {
            for method in [reqwest::Method::GET, reqwest::Method::POST] {
                let response = client
                    .request(method, format!("http://{address}{path}"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 404);
                assert_eq!(response.headers()["x-should-retry"], "false");
                assert_eq!(
                    response.json::<Value>().await.unwrap(),
                    json!({"type":"error","error":{"type":"not_found_error","message":"preflight: The requested route is not registered."}})
                );
                assert_eq!(captured.lock().unwrap().len(), before);
            }
        }
        for (header, value) in [
            ("x-api-key", "local-fixture-key"),
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "fixture-beta"),
            ("authorization", "Bearer local-fixture-key"),
        ] {
            let response = client
                .get(format!("http://{address}/v1/models/fixture"))
                .header(header, value)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 404);
            if header == "authorization" {
                assert!(response.bytes().await.unwrap().is_empty());
            } else {
                assert_eq!(response.headers()["x-should-retry"], "false");
                assert_eq!(
                    response.json::<Value>().await.unwrap()["error"]["type"],
                    "not_found_error"
                );
            }
            assert_eq!(captured.lock().unwrap().len(), before);
        }
        let response = client
            .get(format!("http://{address}/unregistered"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
        assert!(response.bytes().await.unwrap().is_empty());
        proxy.abort();
    }
    upstream_task.abort();
}
