use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use sha2::{Sha256, Digest};

struct AppState {
    users: Mutex<HashMap<u32, User>>,
    sessions: Mutex<HashMap<String, Session>>,
    webhooks: Mutex<HashMap<String, WebhookEntry>>,
}

#[derive(Clone, Serialize)]
struct User {
    id: u32,
    username: String,
    email: String,
    #[serde(skip_serializing)]
    password: String,
    role: String,
    active: bool,
    api_key: String,
}

struct Session {
    user_id: u32,
    created: u64,
}

#[derive(Clone, Serialize)]
struct WebhookEntry {
    id: String,
    callback_url: String,
    event_type: String,
    user_id: u32,
    created: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_token(state: &AppState, user_id: u32) -> String {
    let raw = format!("{}-{}", user_id, now_secs());
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let result = hasher.finalize();
    let token = format!("{:x}", result)[..32].to_string();
    state.sessions.lock().unwrap().insert(token.clone(), Session {
        user_id,
        created: now_secs(),
    });
    token
}

fn get_session<'a>(req: &HttpRequest, sessions: &'a HashMap<String, Session>) -> Option<&'a Session> {
    let auth = req.headers().get("Authorization")?.to_str().ok()?;
    if auth.starts_with("Bearer ") {
        sessions.get(&auth[7..])
    } else {
        None
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(body: web::Json<LoginRequest>, state: web::Data<AppState>) -> HttpResponse {
    let users = state.users.lock().unwrap();
    for (id, user) in users.iter() {
        if user.username == body.username && user.password == body.password {
            if !user.active {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Account disabled"}));
            }
            let token = generate_token(&state, *id);
            return HttpResponse::Ok().json(serde_json::json!({
                "token": token, "user_id": id, "role": user.role
            }));
        }
    }
    HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}))
}

#[derive(Deserialize)]
struct FetchUrlRequest {
    url: String,
}

async fn fetch_url(req: HttpRequest, body: web::Json<FetchUrlRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    if body.url.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "URL parameter required"}));
    }

    match reqwest::get(&body.url).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.text().await {
                Ok(text) => {
                    let preview = if text.len() > 5000 { &text[..5000] } else { &text };
                    HttpResponse::Ok().json(serde_json::json!({
                        "status": status,
                        "content_length": text.len(),
                        "body": preview
                    }))
                }
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e.to_string()}))
            }
        }
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e.to_string()}))
    }
}

async fn preview_link(req: HttpRequest, query: web::Query<HashMap<String, String>>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let target = query.get("target").cloned().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "target parameter required"}));
    }

    if let Ok(parsed) = url::Url::parse(&target) {
        let blocked = vec!["localhost", "127.0.0.1"];
        if let Some(host) = parsed.host_str() {
            if blocked.contains(&host) {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Blocked host"}));
            }
        }
    }

    match reqwest::get(&target).await {
        Ok(resp) => {
            match resp.text().await {
                Ok(text) => {
                    let preview = if text.len() > 2000 { &text[..2000] } else { &text };
                    HttpResponse::Ok().json(serde_json::json!({
                        "url": target,
                        "preview": preview
                    }))
                }
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e.to_string()}))
            }
        }
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e.to_string()}))
    }
}

#[derive(Deserialize)]
struct WebhookRequest {
    callback_url: String,
    event_type: Option<String>,
}

async fn register_webhook(req: HttpRequest, body: web::Json<WebhookRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.user_id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    if body.callback_url.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "callback_url required"}));
    }

    if let Ok(parsed) = url::Url::parse(&body.callback_url) {
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Only HTTP(S) callbacks supported"}));
        }
    } else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid URL"}));
    }

    let webhook_id = format!("{:x}", md5::compute(format!("{}{}", body.callback_url, now_secs())))[..12].to_string();
    let entry = WebhookEntry {
        id: webhook_id.clone(),
        callback_url: body.callback_url.clone(),
        event_type: body.event_type.clone().unwrap_or_else(|| "default".to_string()),
        user_id: session,
        created: now_secs(),
    };

    state.webhooks.lock().unwrap().insert(webhook_id.clone(), entry);
    HttpResponse::Created().json(serde_json::json!({"message": "Webhook registered", "webhook_id": webhook_id}))
}

async fn test_webhook(req: HttpRequest, path: web::Path<String>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let webhook_id = path.into_inner();
    let webhooks = state.webhooks.lock().unwrap();
    let webhook = match webhooks.get(&webhook_id) {
        Some(w) => w.clone(),
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Webhook not found"})),
    };
    drop(webhooks);

    let payload = serde_json::json!({"event": "test", "timestamp": now_secs()});
    let client = reqwest::Client::new();
    match client.post(&webhook.callback_url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Webhook delivered",
                "status": resp.status().as_u16()
            }))
        }
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": format!("Delivery failed: {}", e)}))
    }
}

#[derive(Deserialize)]
struct ImportConfigRequest {
    config_url: String,
}

async fn import_config(req: HttpRequest, body: web::Json<ImportConfigRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    if body.config_url.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "config_url required"}));
    }

    if let Ok(parsed) = url::Url::parse(&body.config_url) {
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Only HTTP(S) URLs supported"}));
        }
        if let Some(host) = parsed.host_str() {
            if host.starts_with("169.254") {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Metadata endpoints not allowed"}));
            }
        }
    }

    match reqwest::get(&body.config_url).await {
        Ok(resp) => {
            match resp.text().await {
                Ok(text) => {
                    match serde_json::from_str::<serde_json::Value>(&text) {
                        Ok(config) => HttpResponse::Ok().json(serde_json::json!({
                            "message": "Configuration imported",
                            "config": config
                        })),
                        Err(_) => HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid JSON at URL"}))
                    }
                }
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e.to_string()}))
            }
        }
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e.to_string()}))
    }
}

async fn proxy_request(req: HttpRequest, query: web::Query<HashMap<String, String>>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let service = query.get("service").cloned().unwrap_or_default();
    let path = query.get("path").cloned().unwrap_or_else(|| "/".to_string());
    let base_url_param = query.get("base_url").cloned().unwrap_or_default();

    let service_map: HashMap<&str, &str> = [
        ("analytics", "http://analytics-service:8081"),
        ("billing", "http://billing-service:8082"),
        ("notifications", "http://notifications-service:8083"),
    ].into_iter().collect();

    let resolved_base = match service_map.get(service.as_str()) {
        Some(base) => base.to_string(),
        None => {
            if base_url_param.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({"error": "Unknown service"}));
            }
            base_url_param
        }
    };

    let full_url = format!("{}{}", resolved_base, path);

    match reqwest::get(&full_url).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            match resp.text().await {
                Ok(text) => {
                    let preview = if text.len() > 5000 { &text[..5000] } else { &text };
                    HttpResponse::Ok().json(serde_json::json!({"status": status, "body": preview}))
                }
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e.to_string()}))
            }
        }
        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({"error": e.to_string()}))
    }
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy", "service": "gateway-api"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut users_map = HashMap::new();
    users_map.insert(1u32, User { id: 1, username: "admin".into(), email: "admin@acmecorp.io".into(), password: "Adm1n_Pr0d!".into(), role: "admin".into(), active: true, api_key: "ak-admin-x7k9m2".into() });
    users_map.insert(2, User { id: 2, username: "jdoe".into(), email: "jdoe@acmecorp.io".into(), password: "JohnD_2024".into(), role: "manager".into(), active: true, api_key: "ak-jdoe-p3q8r1".into() });
    users_map.insert(3, User { id: 3, username: "asmith".into(), email: "asmith@acmecorp.io".into(), password: "alice_pass".into(), role: "developer".into(), active: true, api_key: "ak-asmith-w5t6y4".into() });

    let data = web::Data::new(AppState {
        users: Mutex::new(users_map),
        sessions: Mutex::new(HashMap::new()),
        webhooks: Mutex::new(HashMap::new()),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/api/login", web::post().to(login))
            .route("/api/fetch-url", web::post().to(fetch_url))
            .route("/api/preview", web::get().to(preview_link))
            .route("/api/webhooks", web::post().to(register_webhook))
            .route("/api/webhooks/{id}/test", web::post().to(test_webhook))
            .route("/api/integrations/import", web::post().to(import_config))
            .route("/api/proxy", web::get().to(proxy_request))
            .route("/api/health", web::get().to(health_check))
    })
    .bind("0.0.0.0:8010")?
    .run()
    .await
}
