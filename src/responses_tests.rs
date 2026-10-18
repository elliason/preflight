use super::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn start(router: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, task }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Proxy {
    server: Server,
    _cache: tempfile::TempDir,
}
impl Proxy {
    async fn start(upstream: &Server, mode: Mode) -> Self {
        let cache = tempfile::tempdir().unwrap();
        let config = Config {
            upstream: upstream.url.clone(),
            mode,
            cache_dir: cache.path().to_path_buf(),
            ..Config::default()
        };
        let scanner = Arc::new(scanner(&config).unwrap());
        let attachments = Attachments::new(
            scanner.clone(),
            Arc::new(Mutex::new(Cache::open(cache.path()).unwrap())),
            config.worker.clone(),
            true,
        );
        let app = Arc::new(App {
            config,
            scanner,
            attachments,
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            client_key: None,
            upstream_key: None,
            admission: Arc::new(tokio::sync::Semaphore::new(16)),
        });
        let router = Router::new()
            .route("/v1/responses", post(infer))
            .route("/v1/chat/completions", post(infer))
            .layer(axum::middleware::from_fn(correlation::middleware))
            .with_state(Arc::new(Live {
                current: RwLock::new(app),
            }));
        Self {
            server: Server::start(router).await,
            _cache: cache,
        }
    }
    async fn send(&self, route: &str, body: Vec<u8>) -> reqwest::Response {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}{route}", self.server.url))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap()
    }
}

#[derive(Default)]
struct Capture {
    requests: usize,
    bodies: Vec<Vec<u8>>,
}
async fn capture() -> (Server, Arc<Mutex<Capture>>) {
    let captured = Arc::new(Mutex::new(Capture::default()));
    let state = captured.clone();
    let router = Router::new().fallback(move |request: Request| {
        let state = state.clone();
        async move {
            state.lock().unwrap().requests += 1;
            let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                .await
                .unwrap();
            state.lock().unwrap().bodies.push(bytes.to_vec());
            axum::Json(json!({"output":[]}))
        }
    });
    (Server::start(router).await, captured)
}

fn synthetic_jwt() -> String {
    [
        br#"{"alg":"HS256","typ":"JWT"}"#.as_slice(),
        br#"{"sub":"preflight-canary-not-a-secret","exp":1234567890}"#,
        b"synthetic-signature-not-a-real-session",
    ]
    .map(|part| URL_SAFE_NO_PAD.encode(part))
    .join(".")
}
fn opaque(label: &str) -> String {
    // A non-ASCII marker keeps this synthetic base64url fixture distinct from
    // ordinary prose. U+0080 is UTF-8 here, not a real Fernet/version byte.
    URL_SAFE.encode(format!(
        "\u{80}synthetic opaque state, never provider ciphertext: {label}"
    ))
}
fn item(kind: &str, value: &str) -> Value {
    json!({"type":kind,"id":"opaque_fixture","encrypted_content":value})
}
fn request_with_item(kind: &str, value: &str) -> Value {
    json!({"model":"fixture","input":[item(kind, value),{"role":"user","content":"Public follow-up."}]})
}

#[tokio::test]
async fn opaque_jwt_repro_refuses_before_forwarding() {
    let (upstream, captured) = capture().await;
    let jwt = synthetic_jwt();
    for mode in [Mode::Redact, Mode::NoGo] {
        let proxy = Proxy::start(&upstream, mode).await;
        for kind in ["reasoning", "compaction"] {
            let body = serde_json::to_vec(&request_with_item(kind, &jwt)).unwrap();
            let response = proxy.send("/v1/responses", body).await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
            assert_ne!(response.headers()["x-preflight-finding-count"], "0");
            let error = response.json::<Value>().await.unwrap();
            assert_eq!(error["error"]["code"], "secrets_detected");
            assert!(!error.to_string().contains(&jwt));
            assert!(!error.to_string().contains("[REDACTED:"));
        }
    }
    let captured = captured.lock().unwrap();
    assert_eq!(captured.requests, 0);
    assert!(captured.bodies.is_empty());
}

#[tokio::test]
async fn opaque_refusals_match_structural_refusals() {
    async fn refusal(proxy: &Proxy, body: Value) -> (StatusCode, Value) {
        let response = proxy
            .send("/v1/responses", serde_json::to_vec(&body).unwrap())
            .await;
        let status = response.status();
        assert_eq!(status, StatusCode::CONFLICT);
        let mut body = response.json::<Value>().await.unwrap();
        let ids = body["error"]["finding_ids"].as_array_mut().unwrap();
        assert_eq!(ids.len(), 1);
        // Finding IDs are deliberately fresh; normalize only those values,
        // leaving every key, value type, and other error value for comparison.
        for id in ids {
            assert_eq!(
                uuid::Uuid::parse_str(id.as_str().unwrap())
                    .unwrap()
                    .get_version(),
                Some(uuid::Version::Random)
            );
            *id = json!("<finding-id>");
        }
        (status, body)
    }
    let (upstream, captured) = capture().await;
    let jwt = synthetic_jwt();
    for mode in [Mode::Redact, Mode::NoGo] {
        let proxy = Proxy::start(&upstream, mode).await;
        for field in ["id", "name"] {
            let mut structural = request_with_item("reasoning", &opaque("structural control"));
            structural["input"][0][field] = json!(jwt);
            let expected = refusal(&proxy, structural).await;
            assert_eq!(expected.0, StatusCode::CONFLICT);
            for kind in ["reasoning", "compaction"] {
                assert_eq!(
                    refusal(&proxy, request_with_item(kind, &jwt)).await,
                    expected
                );
            }
        }
    }
    let captured = captured.lock().unwrap();
    assert_eq!(captured.requests, 0);
    assert!(captured.bodies.is_empty());
}

#[tokio::test]
async fn clean_opaque_requests_keep_exact_bytes() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    for kind in ["reasoning", "compaction"] {
        let value = opaque(kind);
        let body = format!(
            " \n{}\t",
            serde_json::to_string_pretty(&request_with_item(kind, &value)).unwrap()
        )
        .into_bytes();
        assert_eq!(
            proxy.send("/v1/responses", body.clone()).await.status(),
            StatusCode::OK
        );
        assert_eq!(captured.lock().unwrap().bodies.last(), Some(&body));
    }
}

#[tokio::test]
async fn opaque_attachment_match_refuses_before_forwarding() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    let jwt = synthetic_jwt();
    // The known attachment has findings. Its identical base64 encoding in an
    // opaque string must refuse the request, rather than forward or rewrite it.
    let encoded = STANDARD.encode(jwt.as_bytes());
    for kind in ["reasoning", "compaction"] {
        let mut body = request_with_item(kind, &encoded);
        body["input"][1]["content"] = json!([
            {"type":"input_text","text":jwt},
            {"type":"input_file","file_data":encoded}
        ]);
        let response = proxy
            .send("/v1/responses", serde_json::to_vec(&body).unwrap())
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"]["code"],
            "secrets_detected"
        );
    }
    let captured = captured.lock().unwrap();
    assert_eq!(captured.requests, 0);
    assert!(captured.bodies.is_empty());
}

#[tokio::test]
async fn other_attachment_redaction_preserves_opaque_state() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    for kind in ["reasoning", "compaction"] {
        let state = opaque(kind);
        let mut body = request_with_item(kind, &state);
        body["input"][1]["content"] =
            json!([{"type":"input_file","file_data":STANDARD.encode(synthetic_jwt())}]);
        assert_eq!(
            proxy
                .send("/v1/responses", serde_json::to_vec(&body).unwrap())
                .await
                .status(),
            StatusCode::OK
        );
        let captured = captured.lock().unwrap();
        let forwarded: Value = serde_json::from_slice(captured.bodies.last().unwrap()).unwrap();
        assert_eq!(forwarded["input"][0]["encrypted_content"], state);
        assert_eq!(
            forwarded["input"][1]["content"][0]["file_data"],
            STANDARD.encode("[REDACTED:jwt]")
        );
    }
}

#[tokio::test]
async fn json_and_data_shapes_keep_legacy_redaction() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    let jwt = synthetic_jwt();
    let cases = [
        (
            json!({"text":jwt}).to_string(),
            json!({"text":"[REDACTED:jwt]"}).to_string(),
        ),
        // The literal value has no complete JWT; decoding the JSON escape is
        // necessary for detection, including after JSON leading whitespace.
        (
            format!(r#"["\u0065{}"]"#, &jwt[1..]),
            json!(["[REDACTED:jwt]"]).to_string(),
        ),
        (
            format!(" \t\n[\"\\u0065{}\"]", &jwt[1..]),
            json!(["[REDACTED:jwt]"]).to_string(),
        ),
        (
            format!("\u{2003}\n{}", json!({"text":jwt})),
            format!("\u{2003}\n{}", json!({"text":"[REDACTED:jwt]"})),
        ),
        (format!("{{ {jwt}"), "{ [REDACTED:jwt]".to_owned()),
        (
            preflight::resolver::data_url(jwt.as_bytes()),
            preflight::resolver::data_url(b"[REDACTED:jwt]"),
        ),
    ];
    for kind in ["reasoning", "compaction"] {
        for (value, expected) in &cases {
            let body = serde_json::to_vec(&request_with_item(kind, value)).unwrap();
            for route in ["/v1/responses", "/v1/chat/completions"] {
                assert_eq!(
                    proxy.send(route, body.clone()).await.status(),
                    StatusCode::OK
                );
                let captured = captured.lock().unwrap();
                let forwarded: Value =
                    serde_json::from_slice(captured.bodies.last().unwrap()).unwrap();
                assert_eq!(forwarded["input"][0]["encrypted_content"], *expected);
            }
            let captured = captured.lock().unwrap();
            let count = captured.bodies.len();
            assert_eq!(captured.bodies[count - 2], captured.bodies[count - 1]);
        }
    }
}

#[tokio::test]
async fn json_and_data_errors_keep_legacy_refusals() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    let jwt = synthetic_jwt();
    for kind in ["reasoning", "compaction"] {
        for value in [
            "data:not-an-attachment".to_owned(),
            format!("data:{jwt}"),
            "data:text/plain;base64,%%%".to_owned(),
            format!("data:text/plain,{jwt}"),
            r#"{"input":[{"type":"input_audio"}]}"#.to_owned(),
            r#"{"image_url":"http://example.invalid/image.png"}"#.to_owned(),
        ] {
            let body = serde_json::to_vec(&request_with_item(kind, &value)).unwrap();
            let mut errors = Vec::new();
            for route in ["/v1/responses", "/v1/chat/completions"] {
                let response = proxy.send(route, body.clone()).await;
                assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
                errors.push(response.json::<Value>().await.unwrap());
            }
            assert_eq!(errors[0], errors[1]);
            assert!(!errors[0].to_string().contains(&jwt));
        }
    }
    let captured = captured.lock().unwrap();
    assert_eq!(captured.requests, 0);
    assert!(captured.bodies.is_empty());
}

#[tokio::test]
async fn json_file_ids_keep_legacy_refusal() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    for kind in ["reasoning", "compaction"] {
        let body =
            serde_json::to_vec(&request_with_item(kind, r#"{"file_id":"fake-file"}"#)).unwrap();
        let response = proxy.send("/v1/responses", body).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"]["code"],
            "attachment_resolution_failed"
        );
    }
    let captured = captured.lock().unwrap();
    assert_eq!(captured.requests, 0);
    assert!(captured.bodies.is_empty());
}

#[tokio::test]
async fn encrypted_content_outside_opaque_items_keeps_redacting() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    let jwt = synthetic_jwt();
    let reasoning = item("reasoning", &jwt);
    let cases = [
        json!({"encrypted_content":jwt}),
        json!({"type":"reasoning","encrypted_content":jwt}),
        json!({"input":[{"encrypted_content":jwt}]}),
        json!({"input":[item("message", &jwt)]}),
        json!({"input":reasoning}),
        json!({"input":[[reasoning.clone()]]}),
        json!({"input":[{"role":"user","content":[reasoning.clone()]}]}),
        json!({"input":[{"type":"function_call","arguments":reasoning.to_string()}]}),
        json!({"input":[{"type":"function_call","arguments":reasoning}]}),
        json!({"input":[{"type":"reasoning","nested":{"encrypted_content":jwt}}]}),
        json!({"input":[{"type":"compaction","encrypted_content":{"text":jwt}}]}),
        json!({"input":[{"type":"reasoning","encrypted_content":[reasoning.clone()]}]}),
        json!({"metadata":{"input":[reasoning.clone()]}}),
        json!({"input":json!({"input":[reasoning.clone()]}).to_string()}),
        json!({"input":[json!({"input":[reasoning.clone()]}).to_string()]}),
        json!({"instructions":[reasoning.clone()]}),
        json!({"output":[reasoning]}),
    ];
    for body in cases {
        assert_eq!(
            proxy
                .send("/v1/responses", serde_json::to_vec(&body).unwrap())
                .await
                .status(),
            StatusCode::OK
        );
        let captured = captured.lock().unwrap();
        let forwarded = std::str::from_utf8(captured.bodies.last().unwrap()).unwrap();
        assert!(!forwarded.contains(&jwt));
        assert!(forwarded.contains("[REDACTED:jwt]"));
    }
    for kind in ["reasoning", "compaction"] {
        let body = serde_json::to_vec(&request_with_item(kind, &jwt)).unwrap();
        assert_eq!(
            proxy.send("/v1/chat/completions", body).await.status(),
            StatusCode::OK
        );
        let captured = captured.lock().unwrap();
        let forwarded: Value = serde_json::from_slice(captured.bodies.last().unwrap()).unwrap();
        assert_eq!(forwarded["input"][0]["encrypted_content"], "[REDACTED:jwt]");
    }
}

#[tokio::test]
async fn reasoning_summary_stays_on_the_redaction_path() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    let jwt = synthetic_jwt();
    let state = opaque("summary control");
    let mut body = request_with_item("reasoning", &state);
    body["input"][0]["summary"] = json!([{"type":"summary_text","text":jwt}]);
    assert_eq!(
        proxy
            .send("/v1/responses", serde_json::to_vec(&body).unwrap())
            .await
            .status(),
        StatusCode::OK
    );
    {
        let captured = captured.lock().unwrap();
        let forwarded: Value = serde_json::from_slice(captured.bodies.last().unwrap()).unwrap();
        assert_eq!(
            forwarded["input"][0]["summary"][0]["text"],
            "[REDACTED:jwt]"
        );
        assert_eq!(forwarded["input"][0]["encrypted_content"], state);
    }
    // The summary remains editable, but a finding in the opaque string of the
    // same item refuses the whole request instead of sending two replacements.
    body["input"][0]["encrypted_content"] = json!(jwt);
    assert_eq!(
        proxy
            .send("/v1/responses", serde_json::to_vec(&body).unwrap())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(captured.lock().unwrap().requests, 1);
}

#[tokio::test]
async fn nonstring_opaque_fields_keep_ordinary_handling() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    for kind in ["reasoning", "compaction"] {
        for value in [Value::Null, json!(false), json!(42), json!([]), json!({})] {
            let mut body = request_with_item(kind, "unused");
            body["input"][0]["encrypted_content"] = value;
            let bytes = serde_json::to_vec(&body).unwrap();
            assert_eq!(
                proxy.send("/v1/responses", bytes.clone()).await.status(),
                StatusCode::OK
            );
            assert_eq!(captured.lock().unwrap().bodies.last(), Some(&bytes));
        }
    }
}

#[tokio::test]
async fn advisory_opaque_findings_preserve_original_policy() {
    let (upstream, captured) = capture().await;
    let proxy = Proxy::start(&upstream, Mode::Advisory).await;
    for kind in ["reasoning", "compaction"] {
        let body = serde_json::to_vec(&request_with_item(kind, &synthetic_jwt())).unwrap();
        let response = proxy.send("/v1/responses", body.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_ne!(response.headers()["x-preflight-finding-count"], "0");
        assert_eq!(captured.lock().unwrap().bodies.last(), Some(&body));
    }
}

#[derive(Default)]
struct Replay {
    turns: usize,
    rejected: usize,
    expected: Vec<Value>,
}
impl Replay {
    fn respond(&mut self, body: Value) -> Response {
        let Some(input) = body["input"].as_array() else {
            self.rejected += 1;
            return StatusCode::BAD_REQUEST.into_response();
        };
        // All prior output items, including their exact opaque strings, must
        // precede the new user message. A changed or missing item is rejected.
        if input.len() != self.expected.len() + 1
            || input[..self.expected.len()] != self.expected
            || input.last().unwrap()["role"] != "user"
        {
            self.rejected += 1;
            return StatusCode::BAD_REQUEST.into_response();
        }
        self.turns += 1;
        let output = match self.turns {
            1 => vec![item("reasoning", &opaque("first turn"))],
            2 => vec![item("compaction", &opaque("compacted history"))],
            _ => vec![item("reasoning", &opaque("resumed turn"))],
        };
        self.expected = output.clone();
        axum::Json(json!({"id":format!("response_{}",self.turns),"object":"response","status":"completed","output":output})).into_response()
    }
}

#[tokio::test]
async fn reasoning_compaction_and_resume_replay_exactly() {
    let replay = Arc::new(Mutex::new(Replay::default()));
    let state = replay.clone();
    let upstream = Server::start(Router::new().route(
        "/v1/responses",
        post(move |axum::Json(body): axum::Json<Value>| {
            let state = state.clone();
            async move { state.lock().unwrap().respond(body) }
        }),
    ))
    .await;
    let mut saved = Vec::<Value>::new();
    {
        let proxy = Proxy::start(&upstream, Mode::Redact).await;
        for turn in 0..3 {
            let mut input = saved.clone();
            input.push(json!({"role":"user","content":format!("Public turn {turn}")}));
            let response = proxy
                .send(
                    "/v1/responses",
                    serde_json::to_vec(&json!({"model":"fixture","store":false,"input":input}))
                        .unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK);
            let response = response.json::<Value>().await.unwrap();
            saved = response["output"].as_array().unwrap().clone();
        }
    }
    // Resume from serialized conversation state using a fresh proxy instance.
    let saved_bytes = serde_json::to_vec(&saved).unwrap();
    let mut input: Vec<Value> = serde_json::from_slice(&saved_bytes).unwrap();
    input.push(json!({"role":"user","content":"Resume the public conversation."}));
    let proxy = Proxy::start(&upstream, Mode::Redact).await;
    let response = proxy
        .send(
            "/v1/responses",
            serde_json::to_vec(&json!({"model":"fixture","store":false,"input":input})).unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let state = replay.lock().unwrap();
    assert_eq!(state.turns, 4);
    assert_eq!(state.rejected, 0);
}

#[test]
fn replay_stub_rejects_changed_or_missing_state() {
    let state_item = item("reasoning", &opaque("stub control"));
    let mut replay = Replay {
        expected: vec![state_item.clone()],
        ..Replay::default()
    };
    for state in [
        vec![],
        vec![item("reasoning", "[REDACTED:jwt]")],
        vec![item("reasoning", &opaque("different state"))],
    ] {
        let mut input = state;
        input.push(json!({"role":"user","content":"Public control."}));
        assert_eq!(
            replay.respond(json!({"input":input})).status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(replay.rejected, 3);
    assert_eq!(
        replay
            .respond(json!({"input":[state_item,{"role":"user","content":"Public control."}]}))
            .status(),
        StatusCode::OK
    );
}
