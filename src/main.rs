use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand, ValueEnum};
use preflight::correlation::{self, RequestId};
use preflight::protocol::{Adapter, Family, RouteSpec};
use preflight::{attachments::Attachments, cache::Cache, document, scanner::Scanner};
use serde::Deserialize;
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::Instrument;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone, Copy, Deserialize, ValueEnum, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    #[default]
    Redact,
    NoGo,
    Advisory,
}
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(long, env = "PREFLIGHT_CONFIG")]
        config: Option<PathBuf>,
    },
    Check {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Cache {
        #[arg(value_parser=["status","purge"])]
        action: String,
        #[arg(long)]
        scope: Option<String>,
        #[arg(
            long,
            env = "PREFLIGHT_CONTROL",
            default_value = "/tmp/preflight-control.sock"
        )]
        socket: PathBuf,
    },
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    bind: String,
    upstream: String,
    mode: Mode,
    cache_dir: PathBuf,
    control_socket: PathBuf,
    worker: PathBuf,
    sandbox: bool,
    carnet: Option<PathBuf>,
    allow_page_redaction: bool,
    cache: preflight::cache::Limits,
    resolver: preflight::resolver::Resolver,
    stopwords: HashSet<String>,
    upstream_entropy: bool,
    max_body_bytes: usize,
    request_timeout_secs: u64,
    anthropic_upstream_auth: AnthropicUpstreamAuth,
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
enum AnthropicUpstreamAuth {
    #[default]
    #[serde(rename = "x-api-key")]
    XApiKey,
    #[serde(rename = "bearer")]
    Bearer,
}
impl Default for Config {
    fn default() -> Self {
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache")
            });
        Self {
            bind: "127.0.0.1:8081".into(),
            upstream: "http://127.0.0.1:8080".into(),
            mode: Mode::Redact,
            cache_dir: base.join("preflight"),
            control_socket: "/tmp/preflight-control.sock".into(),
            worker: std::env::var_os("PREFLIGHT_WORKER")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_exe()
                        .unwrap_or_default()
                        .with_file_name("preflight-worker")
                }),
            sandbox: true,
            carnet: None,
            allow_page_redaction: false,
            cache: Default::default(),
            resolver: Default::default(),
            stopwords: HashSet::new(),
            upstream_entropy: false,
            max_body_bytes: 64 * 1024 * 1024,
            request_timeout_secs: 180,
            anthropic_upstream_auth: AnthropicUpstreamAuth::default(),
        }
    }
}
struct App {
    config: Config,
    scanner: Arc<Scanner>,
    attachments: Attachments,
    client: reqwest::Client,
    client_key: Option<String>,
    upstream_key: Option<String>,
    admission: Arc<tokio::sync::Semaphore>,
}
struct Live {
    current: RwLock<Arc<App>>,
}
impl Live {
    fn snapshot(&self) -> Arc<App> {
        self.current.read().unwrap().clone()
    }
}

fn load(path: Option<PathBuf>) -> Result<Config> {
    let mut c: Config = match path {
        Some(p) => toml::from_str(&std::fs::read_to_string(p)?)?,
        None => Config::default(),
    };
    c.resolver.file_api_key = std::env::var("PREFLIGHT_FILE_API_KEY").ok();
    let url = reqwest::Url::parse(&c.upstream)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none(),
        "invalid upstream"
    );
    anyhow::ensure!(
        c.max_body_bytes > 0 && c.max_body_bytes <= 64 * 1024 * 1024 && c.request_timeout_secs > 0,
        "invalid limits"
    );
    validate_auth_configuration(
        std::env::var("PREFLIGHT_CLIENT_KEY").ok().as_deref(),
        std::env::var("PREFLIGHT_UPSTREAM_KEY").ok().as_deref(),
    )?;
    Ok(c)
}

/// @cc [owner:ghuntley,label:security] authentication-configuration
/// Load and reload MUST reject a local client key without a usable upstream key
/// before publishing a runtime that could fail native authentication forwarding.
fn validate_auth_configuration(client_key: Option<&str>, upstream_key: Option<&str>) -> Result<()> {
    anyhow::ensure!(
        client_key.is_none() || upstream_key.is_some(),
        "a local client key requires an upstream key"
    );
    for key in [client_key, upstream_key].into_iter().flatten() {
        anyhow::ensure!(
            !key.is_empty() && key.parse::<axum::http::HeaderValue>().is_ok(),
            "invalid authentication configuration"
        );
    }
    Ok(())
}
fn scanner(config: &Config) -> Result<Scanner> {
    let hashes = match &config.carnet {
        Some(p) => {
            let v: HashSet<String> = serde_json::from_slice(&std::fs::read(p)?)?;
            anyhow::ensure!(
                v.iter()
                    .all(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())),
                "invalid carnet"
            );
            v.into_iter().map(|s| s.to_lowercase()).collect()
        }
        None => HashSet::new(),
    };
    Scanner::configured(hashes, config.stopwords.clone(), config.upstream_entropy)
}
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_filter(tracing_subscriber::filter::filter_fn(|m| {
                    m.target().starts_with("preflight")
                })),
        )
        .init();
    if run().await.is_err() {
        tracing::error!(event = "startup.failed");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    match Cli::parse().command {
        Commands::Cache {
            action,
            socket,
            scope,
        } => {
            let action = if let Some(scope) = scope {
                anyhow::ensure!(
                    action == "purge"
                        && scope.len() == 64
                        && scope.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid scope"
                );
                format!("purge {scope}")
            } else {
                action
            };
            let mut stream = tokio::net::UnixStream::connect(socket).await?;
            stream.write_all(format!("{action}\n").as_bytes()).await?;
            let mut response = String::new();
            BufReader::new(stream.take(4096))
                .read_line(&mut response)
                .await?;
            print!("{response}");
            Ok(())
        }
        Commands::Check { config } => {
            let c = load(config)?;
            let s = scanner(&c)?;
            println!("{{\"valid\":true,\"profile\":\"{}\"}}", s.profile);
            Ok(())
        }
        Commands::Serve { config } => {
            let config_path = config.clone();
            let config = load(config)?;
            let scanner = Arc::new(scanner(&config)?);
            let cache = Arc::new(Mutex::new(Cache::with_limits(
                &config.cache_dir,
                config.cache.clone(),
            )?));
            let control = bind_control(&config.control_socket).await?;
            let cc = cache.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = control.accept().await {
                    let cc = cc.clone();
                    tokio::spawn(async move {
                        let (read, mut write) = stream.into_split();
                        let mut line = String::new();
                        let read = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            BufReader::new(read.take(128)).read_line(&mut line),
                        )
                        .await;
                        let result = if matches!(read, Ok(Ok(_))) && line.len() < 128 {
                            let mut cache = cc.lock().unwrap();
                            match line.trim() {
                                "purge" => {
                                    cache.purge().map(|_| serde_json::json!({"purged":true}))
                                }
                                "status" => cache.count().map(|n| serde_json::json!({"entries":n})),
                                command if command.starts_with("purge ") => cache
                                    .purge_scope(&command[6..])
                                    .map(|_| serde_json::json!({"purged":true})),
                                _ => Err(anyhow::anyhow!("command")),
                            }
                        } else {
                            Err(anyhow::anyhow!("command"))
                        };
                        let response = result.unwrap_or_else(
                            |_| serde_json::json!({"error":"cache_command_failed"}),
                        );
                        let _ = write.write_all(format!("{response}\n").as_bytes()).await;
                    });
                }
            });
            let sweep_cache = cache.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    interval.tick().await;
                    if sweep_cache.lock().unwrap().sweep().is_err() {
                        tracing::warn!(event = "cache.sweep_failed");
                    }
                }
            });
            let mut attachments = Attachments::new(
                scanner.clone(),
                cache,
                config.worker.clone(),
                config.sandbox,
            );
            attachments.allow_page_redaction = config.allow_page_redaction;
            attachments.check().await?;
            let listener = tokio::net::TcpListener::bind(&config.bind).await?;
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()?;
            tracing::info!(event="service.ready",profile=%scanner.profile);
            let app = Arc::new(App {
                config,
                scanner,
                attachments,
                client,
                client_key: std::env::var("PREFLIGHT_CLIENT_KEY").ok(),
                upstream_key: std::env::var("PREFLIGHT_UPSTREAM_KEY").ok(),
                admission: Arc::new(tokio::sync::Semaphore::new(16)),
            });
            let live = Arc::new(Live {
                current: RwLock::new(app),
            });
            let reload_state = live.clone();
            let mut hangup =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
            tokio::spawn(async move {
                while hangup.recv().await.is_some() {
                    if reload(&reload_state, config_path.clone()).await.is_err() {
                        tracing::warn!(event = "configuration.reload_failed");
                    }
                }
            });
            let router = router(live);
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
            Ok(())
        }
    }
}
fn router(live: Arc<Live>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .route(
            "/metrics",
            get(|| async {
                (
                    [("content-type", "text/plain; version=0.0.4")],
                    preflight::metrics::render(),
                )
            }),
        )
        .route("/v1/models", get(models))
        .route(
            "/v1/responses",
            post(|s, r| infer(s, r, Adapter::Responses)),
        )
        .route(
            "/v1/chat/completions",
            post(|s, r| infer(s, r, Adapter::ChatCompletions)),
        )
        .route(
            "/v1/messages",
            post(|s, r| infer(s, r, Adapter::Messages)).fallback(anthropic_method_not_allowed),
        )
        .route(
            "/v1/messages/count_tokens",
            post(|s, r| infer(s, r, Adapter::CountTokens)).fallback(anthropic_method_not_allowed),
        )
        .layer(axum::middleware::from_fn(correlation::middleware))
        .with_state(live)
}

/// @cc [owner:ghuntley,label:security] atomic-profile-reload
/// A failed reload MUST leave the previous runtime active. Admitted requests MUST
/// retain their immutable runtime snapshot through approval and forwarding.
async fn reload(live: &Live, path: Option<PathBuf>) -> Result<()> {
    let old = live.snapshot();
    let config = load(path)?;
    anyhow::ensure!(
        config.bind == old.config.bind
            && config.cache_dir == old.config.cache_dir
            && config.control_socket == old.config.control_socket
            && config.cache == old.config.cache,
        "restart_required"
    );
    let scanner = Arc::new(scanner(&config)?);
    let mut attachments = Attachments::new(
        scanner.clone(),
        old.attachments.cache.clone(),
        config.worker.clone(),
        config.sandbox,
    );
    attachments.allow_page_redaction = config.allow_page_redaction;
    attachments.slots = old.attachments.slots.clone();
    attachments.scan_slots = old.attachments.scan_slots.clone();
    attachments.check().await?;
    tracing::info!(event="configuration.reloaded",profile=%scanner.profile);
    *live.current.write().unwrap() = Arc::new(App {
        config,
        scanner,
        attachments,
        client: old.client.clone(),
        client_key: old.client_key.clone(),
        upstream_key: old.upstream_key.clone(),
        admission: old.admission.clone(),
    });
    Ok(())
}
async fn bind_control(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    if path.exists() {
        anyhow::ensure!(
            tokio::net::UnixStream::connect(path).await.is_err(),
            "service already active"
        );
        use std::os::unix::fs::FileTypeExt;
        anyhow::ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_socket(),
            "control path occupied"
        );
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
fn error(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        axum::Json(
            serde_json::json!({"error":{"type":"preflight_error","code":code,"message":code}}),
        ),
    )
        .into_response()
}
async fn anthropic_method_not_allowed() -> Response {
    protocol_error(
        Family::Anthropic,
        StatusCode::METHOD_NOT_ALLOWED,
        "invalid_method",
    )
}
fn protocol_error(family: Family, status: StatusCode, code: &'static str) -> Response {
    if family == Family::OpenAi {
        return error(status, code);
    }
    let message = match code {
        "authentication_failed" => "The local client key was not accepted.",
        "invalid_json" => "The request body is not valid supported JSON.",
        "unsupported_content" => "The request contains unsupported content.",
        "secrets_detected" => {
            "The request contains secret findings that cannot be forwarded under this policy."
        }
        "inspection_deadline" => "The inspection or upstream response deadline was exceeded.",
        "body_limit" => "The request body is too large.",
        "invalid_query" => "The request query is not supported.",
        "invalid_method" => "The request method is not supported.",
        "invalid_headers" => "The request headers are not supported.",
        "upstream_configuration" => "The upstream authentication is misconfigured.",
        "upstream_unavailable" | "upstream_redirect_rejected" => {
            "The upstream service is unavailable."
        }
        "inspection_capacity" => "Inspection capacity is temporarily unavailable.",
        _ => "The request could not be inspected completely. No request was forwarded.",
    };
    let status = if status == StatusCode::REQUEST_TIMEOUT {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        status
    };
    let kind = match status {
        StatusCode::UNAUTHORIZED => "authentication_error",
        StatusCode::PAYLOAD_TOO_LARGE => "request_too_large",
        StatusCode::GATEWAY_TIMEOUT => "timeout_error",
        StatusCode::SERVICE_UNAVAILABLE => "overloaded_error",
        status if status.is_server_error() => "api_error",
        _ => "invalid_request_error",
    };
    let mut response = (
        status,
        axum::Json(serde_json::json!({"type":"error","error":{"type":kind,"message":format!("preflight: {message}")}})),
    )
        .into_response();
    if status.is_client_error()
        || matches!(
            code,
            "upstream_configuration" | "upstream_redirect_rejected"
        )
    {
        response
            .headers_mut()
            .insert("x-should-retry", "false".parse().unwrap());
    }
    response
}

// Reasons originate only from the closed classifier and source codecs.
fn native_content_error(reason: &'static str) -> Response {
    let mut response = (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({
        "type":"error", "error":{"type":"invalid_request_error", "message":format!("preflight: {reason}.")}
    }))).into_response();
    response
        .headers_mut()
        .insert("x-should-retry", "false".parse().unwrap());
    response
}

fn native_credentials(headers: &HeaderMap) -> Result<(Option<&str>, Option<&str>)> {
    for name in ["authorization", "x-api-key"] {
        anyhow::ensure!(
            headers.get_all(name).iter().count() <= 1,
            "ambiguous_authentication"
        );
    }
    let bearer = headers
        .get("authorization")
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
                .map(|(_, value)| value)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow::anyhow!("invalid_authentication"))
        })
        .transpose()?;
    let api_key = headers
        .get("x-api-key")
        .map(|value| {
            value
                .to_str()
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow::anyhow!("invalid_authentication"))
        })
        .transpose()?;
    if let (Some(a), Some(b)) = (bearer, api_key) {
        anyhow::ensure!(a == b, "conflicting_authentication");
    }
    Ok((bearer, api_key))
}
fn anthropic_authorized(app: &App, headers: &HeaderMap) -> bool {
    let Ok((bearer, api_key)) = native_credentials(headers) else {
        return false;
    };
    app.client_key
        .as_ref()
        .is_none_or(|key| bearer.or(api_key) == Some(key.as_str()))
}

/// @cc [owner:ghuntley,label:security] native-authentication-boundary
/// A configured local key MUST NOT be forwarded upstream. Anthropic requests
/// MUST send at most one authentication mechanism, including pass-through mode.
/// Replacement credentials MUST use the form validated by configuration parsing.
fn anthropic_upstream_auth(
    app: &App,
    headers: &HeaderMap,
) -> Result<Option<(&'static str, axum::http::HeaderValue)>> {
    if let Some(key) = &app.upstream_key {
        return Ok(Some(match app.config.anthropic_upstream_auth {
            AnthropicUpstreamAuth::XApiKey => ("x-api-key", key.parse()?),
            AnthropicUpstreamAuth::Bearer => ("authorization", format!("Bearer {key}").parse()?),
        }));
    }
    anyhow::ensure!(app.client_key.is_none(), "upstream_configuration");
    let (bearer, api_key) = native_credentials(headers)?;
    if let Some(value) = api_key {
        Ok(Some(("x-api-key", value.parse()?)))
    } else if let Some(value) = bearer {
        Ok(Some(("authorization", format!("Bearer {value}").parse()?)))
    } else {
        Ok(None)
    }
}
fn anthropic_headers_valid(headers: &HeaderMap) -> bool {
    for name in ["anthropic-version", "anthropic-beta", "content-type"] {
        if headers.get_all(name).iter().count() > 1 {
            return false;
        }
        if headers
            .get(name)
            .is_some_and(|value| value.to_str().is_err())
        {
            return false;
        }
    }
    if let Some(version) = headers.get("anthropic-version") {
        let value = version.as_bytes();
        if value.len() != 10
            || !value.iter().enumerate().all(|(i, byte)| {
                if matches!(i, 4 | 7) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_digit()
                }
            })
        {
            return false;
        }
    }
    if let Some(beta) = headers.get("anthropic-beta") {
        let value = beta.to_str().expect("validated header");
        if value.len() > 1024
            || value.split(',').count() > 32
            || !value.split(',').all(|part| {
                let part = part.trim();
                !part.is_empty()
                    && part.len() <= 128
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return false;
        }
    }
    if let Some(content_type) = headers.get("content-type")
        && content_type
            .to_str()
            .expect("validated header")
            .split(';')
            .next()
            .map(str::trim)
            != Some("application/json")
    {
        return false;
    }
    true
}

fn authorized(app: &App, h: &HeaderMap) -> bool {
    app.client_key.as_ref().is_none_or(|k| {
        h.get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {k}"))
    })
}
struct ApprovedRequest {
    bytes: Vec<u8>,
}
/// @cc [owner:ghuntley,label:security] approval-gate
/// Enforcing modes MUST reject binary findings that lack a sanitized replacement;
/// no-go MUST reject every non-allowlisted finding before constructing approval.
fn approve(
    original: &[u8],
    inspection: document::Inspection,
    mode: Mode,
    finding_ids: &[String],
    family: Family,
) -> std::result::Result<ApprovedRequest, Box<Response>> {
    if mode != Mode::Advisory
        && (!inspection.rules.is_empty() && mode == Mode::NoGo || inspection.unsafe_findings)
    {
        if family == Family::Anthropic {
            return Err(Box::new(protocol_error(
                family,
                StatusCode::BAD_REQUEST,
                "secrets_detected",
            )));
        }
        return Err(Box::new((StatusCode::CONFLICT,axum::Json(serde_json::json!({"error":{"type":"preflight_error","code":"secrets_detected","finding_ids":finding_ids}}))).into_response()));
    }
    let bytes = if mode == Mode::Redact && inspection.changed {
        serde_json::to_vec(&inspection.body).map_err(|_| {
            Box::new(protocol_error(
                family,
                StatusCode::BAD_REQUEST,
                "serialization_failed",
            ))
        })?
    } else {
        original.to_vec()
    };
    Ok(ApprovedRequest { bytes })
}
async fn infer(State(live): State<Arc<Live>>, req: Request, adapter: Adapter) -> Response {
    let id = *req
        .extensions()
        .get::<RequestId>()
        .expect("request identity middleware");
    let spec = adapter.route();
    let app = live.snapshot();
    let Ok(_permit) = app.admission.try_acquire() else {
        return protocol_error(
            spec.family,
            StatusCode::SERVICE_UNAVAILABLE,
            "inspection_capacity",
        );
    };
    let start = std::time::Instant::now();
    let mut response = match tokio::time::timeout(
        std::time::Duration::from_secs(app.config.request_timeout_secs),
        inspect_and_forward(&app, req, id, spec).instrument(
            tracing::info_span!("inspection",request_id=%id,profile=%app.scanner.profile),
        ),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => protocol_error(
            spec.family,
            StatusCode::REQUEST_TIMEOUT,
            "inspection_deadline",
        ),
    };
    id.set_header(response.headers_mut());
    tracing::info!(event="request.policy_completed",request_id=%id,status=response.status().as_u16(),duration_ms=start.elapsed().as_millis() as u64);
    preflight::metrics::observe(start.elapsed(), response.status().as_u16());
    response
}
async fn inspect_and_forward(app: &App, req: Request, id: RequestId, spec: RouteSpec) -> Response {
    let fail = |status, code| protocol_error(spec.family, status, code);
    let authorized = match spec.family {
        Family::OpenAi => authorized(app, req.headers()),
        Family::Anthropic => anthropic_authorized(app, req.headers()),
    };
    if !authorized {
        return fail(StatusCode::UNAUTHORIZED, "authentication_failed");
    }
    let target = match spec.target(req.uri()) {
        Ok(target) => target,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_query"),
    };
    if spec.family == Family::Anthropic
        && (!anthropic_headers_valid(req.headers())
            || req
                .headers()
                .get("anthropic-beta")
                .is_some_and(|v| v.to_str().is_ok_and(|v| !app.scanner.scan(v).is_empty())))
    {
        return fail(StatusCode::BAD_REQUEST, "invalid_headers");
    }
    if req.headers().contains_key("content-encoding") {
        return fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content_encoding_unsupported",
        );
    }
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, app.config.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_limit"),
    };
    let plan = match spec.classify(&bytes) {
        Ok(plan) => plan,
        Err(e)
            if matches!(
                e.downcast_ref::<document::PlanError>(),
                Some(document::PlanError::Unsupported)
            ) =>
        {
            return fail(StatusCode::BAD_REQUEST, "unsupported_content");
        }
        Err(e) => {
            if let Some(document::PlanError::Content(reason)) =
                e.downcast_ref::<document::PlanError>()
            {
                return native_content_error(reason);
            }
            return fail(StatusCode::BAD_REQUEST, "invalid_json");
        }
    };
    let scope = preflight::digest(
        parts
            .headers
            .get("authorization")
            .or_else(|| {
                if spec.family == Family::Anthropic {
                    parts.headers.get("x-api-key")
                } else {
                    None
                }
            })
            .map(|v| v.as_bytes())
            .unwrap_or(b"local"),
    );
    let (mut inspection, materialized) = match document::inspect_plan(
        plan,
        &app.config.resolver,
        &app.scanner,
        &app.attachments,
        &scope,
        app.config.mode == Mode::Redact,
        app.config.mode != Mode::Advisory,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => match e.downcast_ref::<document::PlanError>() {
            Some(document::PlanError::Unsupported) => {
                return fail(StatusCode::BAD_REQUEST, "unsupported_content");
            }
            Some(document::PlanError::Content(reason)) => return native_content_error(reason),
            Some(document::PlanError::Acquisition) => {
                return fail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "attachment_resolution_failed",
                );
            }
            None => return fail(StatusCode::UNPROCESSABLE_ENTITY, "inspection_incomplete"),
        },
    };
    inspection.changed |= materialized;
    // Native URL sources are pinned even in advisory mode; visible text stays original.
    let original = if materialized
        && (app.config.mode == Mode::NoGo
            || spec.family == Family::Anthropic && app.config.mode == Mode::Advisory)
    {
        match serde_json::to_vec(&inspection.body) {
            Ok(v) => v,
            Err(_) => return fail(StatusCode::BAD_REQUEST, "serialization_failed"),
        }
    } else {
        bytes.to_vec()
    };
    tracing::info!(
        event = "inspection.completed",
        finding_count = inspection.rules.len()
    );
    preflight::metrics::FINDINGS.fetch_add(
        inspection.rules.len() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    let ids: Vec<String> = document::unique_rules(&inspection.rules)
        .into_iter()
        .map(|rule| {
            let id = uuid::Uuid::new_v4().to_string();
            tracing::warn!(event="inspection.finding",finding_id=%id,rule_id=%rule);
            id
        })
        .collect();
    let finding_count = inspection.rules.len();
    let mut response = match approve(&original, inspection, app.config.mode, &ids, spec.family) {
        Ok(approved) => forward(app, &target, parts.headers, Some(approved), id, spec.family).await,
        Err(r) => *r,
    };
    response.headers_mut().insert(
        "x-preflight-finding-count",
        finding_count.to_string().parse().unwrap(),
    );
    response
}
async fn models(State(live): State<Arc<Live>>, req: Request) -> Response {
    let id = *req
        .extensions()
        .get::<RequestId>()
        .expect("request identity middleware");
    let app = live.snapshot();
    if !authorized(&app, req.headers()) {
        return error(StatusCode::UNAUTHORIZED, "authentication_failed");
    }
    forward(
        &app,
        "/v1/models",
        req.headers().clone(),
        None,
        id,
        Family::OpenAi,
    )
    .await
}
fn strip_headers(headers: &mut HeaderMap) {
    let nominated: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_owned()))
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    ] {
        headers.remove(name);
    }
}
/// @cc [owner:ghuntley,label:security] forward-approved-only
/// Inference body bytes MUST originate from ApprovedRequest. Redirects MUST NOT
/// resend inference content to a different destination.
async fn forward(
    app: &App,
    path: &str,
    mut headers: HeaderMap,
    body: Option<ApprovedRequest>,
    id: RequestId,
    family: Family,
) -> Response {
    let fail = |status, code| protocol_error(family, status, code);
    let native_auth = if family == Family::Anthropic {
        anthropic_upstream_auth(app, &headers)
    } else {
        Ok(None)
    };
    strip_headers(&mut headers);
    // Apply after hop-by-hop stripping: Connection must not remove our identity.
    id.set_header(&mut headers);
    headers.remove("x-preflight-request-id");
    headers.remove("accept-encoding");
    if family == Family::Anthropic {
        headers.remove("authorization");
        headers.remove("x-api-key");
        match native_auth {
            Ok(Some((name, value))) => {
                headers.insert(name, value);
            }
            Ok(None) => {}
            Err(_) => return fail(StatusCode::INTERNAL_SERVER_ERROR, "upstream_configuration"),
        }
    } else if let Some(key) = &app.upstream_key {
        match format!("Bearer {key}").parse() {
            Ok(value) => {
                headers.insert("authorization", value);
            }
            Err(_) => return fail(StatusCode::INTERNAL_SERVER_ERROR, "upstream_configuration"),
        }
    }
    let url = format!("{}{}", app.config.upstream.trim_end_matches('/'), path);
    let request = match body {
        Some(b) => app.client.post(url).headers(headers).body(b.bytes),
        None => app.client.get(url).headers(headers),
    };
    match request.send().await {
        Ok(upstream) => {
            let status = upstream.status();
            if status.is_redirection() {
                return fail(StatusCode::BAD_GATEWAY, "upstream_redirect_rejected");
            }
            let mut headers = upstream.headers().clone();
            strip_headers(&mut headers);
            let stream = ObservedStream {
                inner: Box::pin(upstream.bytes_stream()),
                span: tracing::Span::current(),
                finished: false,
                bytes: 0,
                started: std::time::Instant::now(),
            };
            let mut response = Response::new(Body::from_stream(stream));
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            response
        }
        Err(_) => fail(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
    }
}
struct ObservedStream {
    inner: std::pin::Pin<
        Box<
            dyn futures::Stream<Item = std::result::Result<axum::body::Bytes, reqwest::Error>>
                + Send,
        >,
    >,
    span: tracing::Span,
    finished: bool,
    bytes: u64,
    started: std::time::Instant,
}
impl futures::Stream for ObservedStream {
    type Item = std::result::Result<axum::body::Bytes, reqwest::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let result = self.inner.as_mut().poll_next(cx);
        match &result {
            std::task::Poll::Ready(Some(Ok(bytes))) => self.bytes += bytes.len() as u64,
            std::task::Poll::Ready(Some(Err(_))) => {
                self.finished = true;
                let _entered = self.span.enter();
                tracing::warn!(event = "response.stream_failed");
            }
            std::task::Poll::Ready(None) => {
                self.finished = true;
                let _entered = self.span.enter();
                tracing::info!(
                    event = "response.completed",
                    bytes = self.bytes,
                    duration_ms = self.started.elapsed().as_millis() as u64
                );
            }
            _ => {}
        }
        result
    }
}
impl Drop for ObservedStream {
    fn drop(&mut self) {
        if !self.finished {
            let _entered = self.span.enter();
            tracing::info!(event = "response.cancelled", bytes = self.bytes);
        }
    }
}

#[cfg(test)]
mod policy_properties {
    use super::*;
    use hegel::{TestCase, generators as gs};
    #[test]
    fn authentication_configuration_rejects_unusable_native_forwarding() {
        assert!(validate_auth_configuration(None, None).is_ok());
        assert!(validate_auth_configuration(None, Some("fake-upstream-key")).is_ok());
        assert!(
            validate_auth_configuration(Some("fake-local-key"), Some("fake-upstream-key")).is_ok()
        );
        assert!(validate_auth_configuration(Some("fake-local-key"), None).is_err());
        for invalid in ["", "fake\nkey", "fake\rkey"] {
            assert!(validate_auth_configuration(None, Some(invalid)).is_err());
            assert!(validate_auth_configuration(Some(invalid), Some("fake-upstream-key")).is_err());
        }
    }

    #[hegel::test]
    fn local_authentication_always_requires_upstream_credentials(tc: TestCase) {
        let local = tc.draw(gs::text());
        assert!(validate_auth_configuration(Some(&local), None).is_err());
    }

    #[hegel::test]
    fn enforcing_policy_never_approves_unrewritable_findings(tc: TestCase) {
        let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(20));
        let no_go = tc.draw(gs::integers::<u8>().min_value(0).max_value(1)) == 1;
        let inspection = document::Inspection {
            body: serde_json::json!({"input":"sanitized"}),
            rules: vec!["test-rule".into(); count],
            changed: true,
            unsafe_findings: true,
        };
        let mode = if no_go { Mode::NoGo } else { Mode::Redact };
        assert!(
            approve(
                b"original",
                inspection,
                mode,
                &["opaque".into()],
                Family::OpenAi
            )
            .is_err()
        );
    }
    #[hegel::test]
    fn advisory_always_preserves_original_bytes_after_complete_inspection(tc: TestCase) {
        let text = tc.draw(gs::text());
        let original = serde_json::to_vec(&serde_json::json!({"input":text})).unwrap();
        let inspection = document::Inspection {
            body: serde_json::json!({"input":"changed"}),
            rules: vec!["test-rule".into()],
            changed: true,
            unsafe_findings: true,
        };
        let approved = approve(&original, inspection, Mode::Advisory, &[], Family::OpenAi).unwrap();
        assert_eq!(approved.bytes, original);
    }
}

#[cfg(test)]
mod proxy_tests;

#[cfg(test)]
mod legacy_http_tests;
