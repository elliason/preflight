//! HTTP fixtures captured from eb13fc0; see tests/fixtures/legacy-http.md.
use super::*;
use axum::{body::Bytes, http::Method, http::Uri};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

const BASE: &str = "eb13fc015686202d15c7ed57faa3d975482bcc32";
const UUID: &str = "00000000-0000-4000-8000-000000000000";
const BODY_LIMIT: usize = 4096;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Exchange {
    status: u16,
    headers: BTreeMap<String, Vec<String>>,
    body: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Forwarded {
    method: String,
    target: String,
    headers: BTreeMap<String, Vec<String>>,
    body: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Golden {
    path: String,
    mode: String,
    case: String,
    response: Exchange,
    forwarded: Vec<Forwarded>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Fixtures {
    base_revision: String,
    cases: Vec<Golden>,
}

struct Case {
    name: &'static str,
    body: String,
    credential: Option<&'static str>,
    encoding: Option<&'static str>,
    upstream_reply: &'static str,
    rejects_without_forwarding: bool,
}

fn fake_jwt() -> String {
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        encoder.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        encoder.encode(br#"{"sub":"preflight-canary-not-a-secret"}"#),
        encoder.encode(b"fake-signature-never-valid")
    )
}

fn cases(path: &str) -> Vec<Case> {
    let clean = if path == "/v1/responses" {
        "{ \"model\": \"fixture\", \"input\": \"hello\", \"stream\": true }\n"
    } else {
        "{ \"model\": \"fixture\", \"messages\": [{\"role\":\"user\",\"content\":\"hello\"}], \"stream\": true }\n"
    };
    let input = |text: &str| {
        if path == "/v1/responses" {
            json!({"model":"fixture", "input":text})
        } else {
            json!({"model":"fixture", "messages":[{"role":"user", "content":text}]})
        }
        .to_string()
    };
    let mut cases = Vec::new();
    for (name, body, rejected) in [
        ("clean", clean.into(), false),
        ("editable", input(&fake_jwt()), false),
        ("structural", json!({"model":fake_jwt(), "input":"hello"}).to_string(), false),
        ("nested-json", json!({"tool":json!({"nested":fake_jwt(),"number":7}).to_string()}).to_string(), false),
        ("text-attachment", json!({"input":[{"type":"input_file","file_data":base64::engine::general_purpose::STANDARD.encode(fake_jwt())}]}).to_string(), false),
        ("split-text", json!({"input":[{"type":"input_text","text":"-----BEGIN PRIVATE KEY-----"},{"type":"input_text","text":"synthetic\n-----END PRIVATE KEY-----"}]}).to_string(), false),
        ("malformed", "{malformed".into(), true),
        ("duplicate-key", r#"{"input":"a","input":"b"}"#.into(), true),
        ("nested-duplicate-key", r#"{"input":{"text":"a","text":"b"}}"#.into(), true),
        ("non-object", "[]".into(), true),
        ("body-limit", " ".repeat(BODY_LIMIT + 1), true),
        ("unresolved-reference", json!({"file_id":"file-fixture-missing"}).to_string(), true),
        ("bad-attachment", json!({"file_data":"%%%"}).to_string(), true),
        ("unsupported-audio", json!({"input":[{"type":"input_audio","data":"fake"}]}).to_string(), true),
    ] {
        cases.push(Case {
            name,
            body,
            credential: Some("Bearer local-fixture-key"),
            encoding: None,
            upstream_reply: "success",
            rejects_without_forwarding: rejected,
        });
    }
    for (name, credential, encoding, body, upstream_reply, rejected) in [
        ("missing-auth", None, None, clean, "success", true),
        (
            "wrong-auth",
            Some("Bearer wrong-fixture-key"),
            None,
            clean,
            "success",
            true,
        ),
        (
            "auth-before-encoding-and-json",
            None,
            Some("gzip"),
            "{malformed",
            "success",
            true,
        ),
        (
            "encoding-before-json",
            Some("Bearer local-fixture-key"),
            Some("gzip"),
            "{malformed",
            "success",
            true,
        ),
        (
            "opaque-upstream-error",
            Some("Bearer local-fixture-key"),
            None,
            clean,
            "error",
            false,
        ),
        (
            "upstream-redirect",
            Some("Bearer local-fixture-key"),
            None,
            clean,
            "redirect",
            false,
        ),
    ] {
        cases.push(Case {
            name,
            body: body.into(),
            credential,
            encoding,
            upstream_reply,
            rejects_without_forwarding: rejected,
        });
    }
    cases
}

fn normalize_headers(
    headers: &HeaderMap,
    upstream_host: Option<&str>,
) -> BTreeMap<String, Vec<String>> {
    let mut normalized = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in headers {
        let value = value.to_str().unwrap();
        let value = match name.as_str() {
            "x-request-id" => {
                assert_eq!(uuid::Uuid::parse_str(value).unwrap().get_version_num(), 4);
                UUID
            }
            "date" => {
                assert_eq!(value.len(), 29);
                assert!(value.ends_with(" GMT"));
                "<date>"
            }
            "host" => {
                assert_eq!(Some(value), upstream_host);
                "<upstream>"
            }
            _ => value,
        };
        normalized
            .entry(name.to_string())
            .or_default()
            .push(value.into());
    }
    normalized
}

fn normalize_body(status: u16, body: Bytes) -> String {
    let mut body = String::from_utf8(body.to_vec()).unwrap();
    // Preserve the exact JSON envelope/whitespace and UUID lengths. Only IDs
    // generated by preflight vary between runs, never user or upstream content.
    if status == 409 {
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let ids = parsed["error"]["finding_ids"].as_array().unwrap();
        assert!(!ids.is_empty());
        for id in ids {
            let id = id.as_str().unwrap();
            assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 4);
            body = body.replace(id, UUID);
        }
    }
    body
}

fn app(dir: &std::path::Path, upstream: String, mode: Mode) -> App {
    let scanner = Arc::new(Scanner::new(HashSet::new()).unwrap());
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
            max_body_bytes: BODY_LIMIT,
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

async fn observe_legacy_http() -> Fixtures {
    let mut cases_observed = Vec::new();
    for path in ["/v1/responses", "/v1/chat/completions"] {
        for (mode_name, mode) in [
            ("redact", Mode::Redact),
            ("no-go", Mode::NoGo),
            ("advisory", Mode::Advisory),
        ] {
            let captured = Arc::new(Mutex::new(Vec::<Forwarded>::new()));
            let seen = captured.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_address = listener.local_addr().unwrap();
            let upstream = Router::new().fallback(
                move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push(Forwarded {
                            method: method.to_string(),
                            target: uri.to_string(),
                            headers: normalize_headers(
                                &headers,
                                Some(&upstream_address.to_string()),
                            ),
                            body: String::from_utf8(body.to_vec()).unwrap(),
                        });
                        let status = match headers["x-fixture-reply"].to_str().unwrap() {
                            "success" => StatusCode::CREATED,
                            "error" => StatusCode::TOO_MANY_REQUESTS,
                            "redirect" => StatusCode::TEMPORARY_REDIRECT,
                            _ => unreachable!(),
                        };
                        (
                            status,
                            [
                                ("content-type", "application/json"),
                                ("date", "Mon, 01 Jan 2024 00:00:00 GMT"),
                                ("x-upstream-fixture", "preserved"),
                                ("connection", "x-drop-response"),
                                ("x-drop-response", "removed"),
                                ("x-request-id", "upstream-supplied-id"),
                                ("x-preflight-request-id", "upstream-legacy-id"),
                                ("location", "/must-not-follow"),
                            ],
                            "{ \"fixture\": \"opaque upstream bytes\" }\n",
                        )
                    }
                },
            );
            let upstream_task =
                tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
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
            let router = router(live);
            let proxy = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let client = reqwest::Client::new();
            for case in cases(path) {
                let mut request = client
                    .post(format!(
                        "http://{address}{path}?legacy=discarded&beta=false"
                    ))
                    .header("content-type", "application/json")
                    .header("x-api-key", "legacy-fixture-passthrough")
                    .header("anthropic-version", "legacy-unvalidated")
                    .header("anthropic-beta", "legacy/unvalidated")
                    .header("accept-encoding", "gzip")
                    .header("connection", "x-drop-request, x-request-id")
                    .header("x-drop-request", "removed")
                    .header("x-request-id", "client-supplied-id")
                    .header("x-preflight-request-id", "client-legacy-id")
                    .header("x-fixture-reply", case.upstream_reply)
                    .body(case.body);
                if let Some(credential) = case.credential {
                    request = request.header("authorization", credential);
                }
                if let Some(encoding) = case.encoding {
                    request = request.header("content-encoding", encoding);
                }
                let response = request.send().await.unwrap();
                let status = response.status().as_u16();
                let request_id = response.headers()["x-request-id"].clone();
                let headers = normalize_headers(response.headers(), None);
                let body = normalize_body(status, response.bytes().await.unwrap());
                let forwarded = std::mem::take(&mut *captured.lock().unwrap());
                if case.rejects_without_forwarding || status == 409 {
                    assert!(forwarded.is_empty(), "{path} {mode_name} {}", case.name);
                    assert!(matches!(status, 400 | 401 | 409 | 413 | 415 | 422));
                } else {
                    assert_eq!(forwarded.len(), 1, "{path} {mode_name} {}", case.name);
                    assert_eq!(forwarded[0].target, path);
                }
                assert_eq!(
                    uuid::Uuid::parse_str(request_id.to_str().unwrap())
                        .unwrap()
                        .get_version_num(),
                    4
                );
                cases_observed.push(Golden {
                    path: path.into(),
                    mode: mode_name.into(),
                    case: case.name.into(),
                    response: Exchange {
                        status,
                        headers,
                        body,
                    },
                    forwarded,
                });
            }
            proxy.abort();
            upstream_task.abort();
        }
    }
    Fixtures {
        base_revision: BASE.into(),
        cases: cases_observed,
    }
}

#[tokio::test]
async fn legacy_routes_match_base_http_goldens_in_every_mode() {
    let expected: Fixtures =
        serde_json::from_str(include_str!("../tests/fixtures/legacy-http-eb13fc0.json")).unwrap();
    let actual = observe_legacy_http().await;
    assert_eq!(expected.base_revision, BASE);
    assert_eq!(actual.cases.len(), expected.cases.len());
    for (actual, expected) in actual.cases.iter().zip(&expected.cases) {
        assert_eq!(
            actual, expected,
            "{} {} {}",
            actual.path, actual.mode, actual.case
        );
    }
}

#[tokio::test]
#[ignore = "fixture generation: run only against eb13fc0 as documented"]
async fn capture_legacy_http_goldens() {
    let fixtures = observe_legacy_http().await;
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy-http-eb13fc0.json"
        ),
        format!("{}\n", serde_json::to_string_pretty(&fixtures).unwrap()),
    )
    .unwrap();
}
