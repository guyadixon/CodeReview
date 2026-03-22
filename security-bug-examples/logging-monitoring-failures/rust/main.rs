use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Serialize, Deserialize)]
struct User {
    id: u32,
    username: String,
    email: String,
    password: String,
    role: String,
    active: bool,
    mfa_enabled: bool,
    api_key: String,
}

#[derive(Clone)]
struct Session {
    user_id: u32,
    created: u64,
}

#[derive(Clone, Serialize)]
struct Transaction {
    id: u32,
    user_id: u32,
    amount: f64,
    recipient: String,
    description: String,
    timestamp: u64,
    status: String,
}

struct AppState {
    users: Mutex<HashMap<u32, User>>,
    sessions: Mutex<HashMap<String, Session>>,
    transactions: Mutex<Vec<Transaction>>,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn generate_token(state: &AppState, user_id: u32) -> String {
    let raw = format!("{}-{}", user_id, now_secs());
    let hash = Sha256::digest(raw.as_bytes());
    let token: String = format!("{:x}", hash).chars().take(32).collect();
    let mut sessions = state.sessions.lock().unwrap();
    sessions.insert(token.clone(), Session { user_id, created: now_secs() });
    token
}

fn get_session<'a>(req: &HttpRequest, sessions: &'a HashMap<String, Session>) -> Option<&'a Session> {
    let auth = req.headers().get("Authorization")?.to_str().ok()?;
    if auth.starts_with("Bearer ") {
        return sessions.get(&auth[7..]);
    }
    None
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(body: web::Json<LoginRequest>, state: web::Data<AppState>) -> HttpResponse {
    let mut users = state.users.lock().unwrap();

    for (uid, user) in users.iter_mut() {
        if user.username == body.username {
            if !user.active {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Account disabled"
                }));
            }

            if user.password == body.password {
                let token = generate_token(&state, *uid);
                return HttpResponse::Ok().json(serde_json::json!({
                    "token": token,
                    "user_id": uid,
                    "role": user.role,
                    "password": user.password,
                    "api_key": user.api_key
                }));
            }

            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            }));
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}))
}

async fn list_users(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let users = state.users.lock().unwrap();
    let result: Vec<serde_json::Value> = users.values().map(|u| {
        serde_json::json!({
            "id": u.id, "username": u.username, "email": u.email,
            "role": u.role, "active": u.active
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"users": result}))
}

#[derive(Deserialize)]
struct RoleChangeRequest {
    role: String,
}

async fn change_role(req: HttpRequest, path: web::Path<u32>, body: web::Json<RoleChangeRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let target_id = path.into_inner();
    let mut users = state.users.lock().unwrap();

    match users.get_mut(&target_id) {
        Some(target) => {
            let old_role = target.role.clone();
            target.role = body.role.clone();
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Role updated",
                "user_id": target_id,
                "old_role": old_role,
                "new_role": body.role
            }))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Target user not found"})),
    }
}

async fn deactivate_user(req: HttpRequest, path: web::Path<u32>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let mut users = state.users.lock().unwrap();
    let caller = match users.get(&session.user_id) {
        Some(u) if u.role == "admin" => true,
        _ => false,
    };

    if !caller {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Admin access required"}));
    }

    let target_id = path.into_inner();
    match users.get_mut(&target_id) {
        Some(target) => {
            target.active = false;
            HttpResponse::Ok().json(serde_json::json!({"message": "User deactivated", "user_id": target_id}))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Target user not found"})),
    }
}

#[derive(Deserialize)]
struct TransactionRequest {
    amount: Option<f64>,
    recipient: String,
    description: Option<String>,
}

async fn create_transaction(req: HttpRequest, body: web::Json<TransactionRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    if body.recipient.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Recipient required"}));
    }

    let mut txns = state.transactions.lock().unwrap();
    let tx = Transaction {
        id: txns.len() as u32 + 1,
        user_id: session.user_id,
        amount: body.amount.unwrap_or(0.0),
        recipient: body.recipient.clone(),
        description: body.description.clone().unwrap_or_default(),
        timestamp: now_secs(),
        status: "completed".to_string(),
    };
    txns.push(tx.clone());

    HttpResponse::Created().json(serde_json::json!({"message": "Transaction completed", "transaction": tx}))
}

#[derive(Deserialize)]
struct BulkTransferRequest {
    transfers: Vec<TransactionRequest>,
}

async fn bulk_transfer(req: HttpRequest, body: web::Json<BulkTransferRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let mut txns = state.transactions.lock().unwrap();
    let mut results = Vec::new();

    for t in &body.transfers {
        let tx = Transaction {
            id: txns.len() as u32 + 1,
            user_id: session.user_id,
            amount: t.amount.unwrap_or(0.0),
            recipient: t.recipient.clone(),
            description: t.description.clone().unwrap_or_default(),
            timestamp: now_secs(),
            status: "completed".to_string(),
        };
        txns.push(tx.clone());
        results.push(tx);
    }

    HttpResponse::Created().json(serde_json::json!({
        "message": format!("{} transfers completed", results.len()),
        "transactions": results
    }))
}

#[derive(Deserialize)]
struct ExportRequest {
    #[serde(rename = "type")]
    export_type: String,
}

async fn export_data(req: HttpRequest, body: web::Json<ExportRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    if body.export_type == "users" {
        let users = state.users.lock().unwrap();
        let export: Vec<serde_json::Value> = users.values().map(|u| {
            serde_json::json!({
                "id": u.id, "username": u.username, "email": u.email,
                "password": u.password, "api_key": u.api_key, "role": u.role
            })
        }).collect();
        return HttpResponse::Ok().json(serde_json::json!({"export": export}));
    }

    if body.export_type == "transactions" {
        let txns = state.transactions.lock().unwrap();
        return HttpResponse::Ok().json(serde_json::json!({"export": *txns}));
    }

    HttpResponse::BadRequest().json(serde_json::json!({"error": "Unknown export type"}))
}

async fn regenerate_api_key(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let mut users = state.users.lock().unwrap();
    match users.get_mut(&session.user_id) {
        Some(user) => {
            let old_key = user.api_key.clone();
            let raw = format!("{}{}", user.username, now_secs());
            let hash = Sha256::digest(raw.as_bytes());
            let new_key = format!("ak-{}", &format!("{:x}", hash)[..12]);
            user.api_key = new_key.clone();
            HttpResponse::Ok().json(serde_json::json!({
                "message": "API key regenerated",
                "old_key": old_key,
                "new_key": new_key
            }))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

#[derive(Deserialize)]
struct MfaRequest {
    enabled: bool,
}

async fn toggle_mfa(req: HttpRequest, body: web::Json<MfaRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let mut users = state.users.lock().unwrap();
    match users.get_mut(&session.user_id) {
        Some(user) => {
            user.mfa_enabled = body.enabled;
            HttpResponse::Ok().json(serde_json::json!({
                "message": "MFA setting updated",
                "mfa_enabled": body.enabled
            }))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

#[derive(Deserialize)]
struct ValidateKeyRequest {
    api_key: String,
}

async fn validate_key(body: web::Json<ValidateKeyRequest>, state: web::Data<AppState>) -> HttpResponse {
    let users = state.users.lock().unwrap();

    for user in users.values() {
        if user.api_key == body.api_key {
            return HttpResponse::Ok().json(serde_json::json!({
                "valid": true,
                "user_id": user.id,
                "username": user.username,
                "role": user.role
            }));
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({"valid": false}))
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy", "service": "logging-api"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        users: Mutex::new({
            let mut m = HashMap::new();
            m.insert(1, User { id: 1, username: "admin".into(), email: "admin@acmecorp.io".into(),
                password: "Adm1n_Pr0d!".into(), role: "admin".into(), active: true,
                mfa_enabled: true, api_key: "ak-admin-x7k9m2".into() });
            m.insert(2, User { id: 2, username: "jdoe".into(), email: "jdoe@acmecorp.io".into(),
                password: "JohnD_2024".into(), role: "manager".into(), active: true,
                mfa_enabled: false, api_key: "ak-jdoe-p3q8r1".into() });
            m.insert(3, User { id: 3, username: "asmith".into(), email: "asmith@acmecorp.io".into(),
                password: "alice_pass".into(), role: "developer".into(), active: true,
                mfa_enabled: false, api_key: "ak-asmith-w5t6y4".into() });
            m.insert(4, User { id: 4, username: "bwilson".into(), email: "bwilson@acmecorp.io".into(),
                password: "B0b_W1ls0n".into(), role: "analyst".into(), active: false,
                mfa_enabled: false, api_key: "ak-bwilson-z2v8n3".into() });
            m
        }),
        sessions: Mutex::new(HashMap::new()),
        transactions: Mutex::new(Vec::new()),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/api/login", web::post().to(login))
            .route("/api/admin/users", web::get().to(list_users))
            .route("/api/admin/users/{id}/role", web::put().to(change_role))
            .route("/api/admin/users/{id}/deactivate", web::post().to(deactivate_user))
            .route("/api/transactions", web::post().to(create_transaction))
            .route("/api/transactions/bulk", web::post().to(bulk_transfer))
            .route("/api/export/data", web::post().to(export_data))
            .route("/api/settings/api-key", web::post().to(regenerate_api_key))
            .route("/api/settings/mfa", web::put().to(toggle_mfa))
            .route("/api/validate-key", web::post().to(validate_key))
            .route("/api/health", web::get().to(health_check))
    })
    .bind("0.0.0.0:8099")?
    .run()
    .await
}
