use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
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
    failed_attempts: u32,
}

#[derive(Clone)]
struct Session {
    user_id: u32,
    created: u64,
}

struct AppState {
    users: Mutex<HashMap<u32, User>>,
    sessions: Mutex<HashMap<String, Session>>,
    reset_tokens: Mutex<HashMap<String, u32>>,
}

const DB_CONNECTION: &str = "postgresql://appuser:Pg_Pr0d#2024@db.internal.acmecorp.io:5432/designdb";
const SMTP_HOST: &str = "mail.internal.acmecorp.io";
const SMTP_PASSWORD: &str = "SmtpR3lay#2024!";

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn compute_md5(input: &str) -> String {
    let digest = md5::compute(input.as_bytes());
    format!("{:x}", digest)
}

fn generate_session_token(state: &AppState, user_id: u32) -> String {
    let raw = format!("{}-{}", user_id, now_secs());
    let hash = sha2::Sha256::digest(raw.as_bytes());
    let token = format!("{:x}", hash).chars().take(32).collect::<String>();
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

use sha2::Digest;

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
                    "error": format!("Account '{}' is deactivated. Contact admin@acmecorp.io.", body.username)
                }));
            }

            if user.password == body.password {
                user.failed_attempts = 0;
                let token = generate_session_token(&state, *uid);
                return HttpResponse::Ok().json(serde_json::json!({
                    "token": token, "user_id": uid, "role": user.role
                }));
            }

            user.failed_attempts += 1;
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Incorrect password",
                "attempts": user.failed_attempts
            }));
        }
    }

    HttpResponse::NotFound().json(serde_json::json!({
        "error": format!("No account found for username '{}'", body.username)
    }))
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

async fn register(body: web::Json<RegisterRequest>, state: web::Data<AppState>) -> HttpResponse {
    if body.username.is_empty() || body.email.is_empty() || body.password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "All fields required"}));
    }

    let mut users = state.users.lock().unwrap();

    for user in users.values() {
        if user.username == body.username {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": format!("Username '{}' is already taken", body.username)
            }));
        }
        if user.email == body.email {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": format!("Email '{}' is already registered", body.email)
            }));
        }
    }

    let new_id = users.keys().max().copied().unwrap_or(0) + 1;
    users.insert(new_id, User {
        id: new_id,
        username: body.username.clone(),
        email: body.email.clone(),
        password: body.password.clone(),
        role: "viewer".to_string(),
        active: true,
        failed_attempts: 0,
    });

    HttpResponse::Created().json(serde_json::json!({"message": "User registered", "user_id": new_id}))
}

#[derive(Deserialize)]
struct ResetRequest {
    email: String,
}

async fn request_password_reset(body: web::Json<ResetRequest>, state: web::Data<AppState>) -> HttpResponse {
    let users = state.users.lock().unwrap();

    for (uid, user) in users.iter() {
        if user.email == body.email {
            let raw = format!("{}{}", body.email, now_secs());
            let token = compute_md5(&raw).chars().take(16).collect::<String>();
            let mut tokens = state.reset_tokens.lock().unwrap();
            tokens.insert(token.clone(), *uid);

            return HttpResponse::Ok().json(serde_json::json!({
                "message": "Password reset link sent",
                "token": token,
                "smtp_server": SMTP_HOST
            }));
        }
    }

    HttpResponse::NotFound().json(serde_json::json!({
        "error": format!("No account associated with '{}'", body.email)
    }))
}

#[derive(Deserialize)]
struct ResetConfirmRequest {
    token: String,
    new_password: String,
}

async fn confirm_password_reset(body: web::Json<ResetConfirmRequest>, state: web::Data<AppState>) -> HttpResponse {
    let mut tokens = state.reset_tokens.lock().unwrap();
    let uid = match tokens.get(&body.token) {
        Some(uid) => *uid,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid or expired token"})),
    };

    let mut users = state.users.lock().unwrap();
    if let Some(user) = users.get_mut(&uid) {
        user.password = body.new_password.clone();
        tokens.remove(&body.token);
        return HttpResponse::Ok().json(serde_json::json!({"message": "Password updated successfully"}));
    }

    HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}))
}

async fn get_current_user(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let users = state.users.lock().unwrap();
    match users.get(&session.user_id) {
        Some(user) => HttpResponse::Ok().json(serde_json::json!({
            "id": user.id, "username": user.username,
            "email": user.email, "role": user.role
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    new_password: String,
}

async fn change_password(req: HttpRequest, body: web::Json<ChangePasswordRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let mut users = state.users.lock().unwrap();
    match users.get_mut(&session.user_id) {
        Some(user) => {
            user.password = body.new_password.clone();
            HttpResponse::Ok().json(serde_json::json!({"message": "Password updated"}))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

#[derive(Deserialize)]
struct ReportRequest {
    #[serde(rename = "type")]
    report_type: String,
}

async fn generate_report(req: HttpRequest, body: web::Json<ReportRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let result: Result<String, String> = Err(format!(
        "Failed to connect to database at '{}': connection refused", DB_CONNECTION
    ));

    match result {
        Ok(data) => HttpResponse::Ok().json(serde_json::json!({"report": data})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Report generation failed",
            "details": e,
            "connection_string": DB_CONNECTION
        })),
    }
}

async fn get_config(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let users = state.users.lock().unwrap();
    match users.get(&session.user_id) {
        Some(user) if user.role == "admin" => {
            let session_count = state.sessions.lock().unwrap().len();
            HttpResponse::Ok().json(serde_json::json!({
                "database_connection": DB_CONNECTION,
                "smtp_host": SMTP_HOST,
                "smtp_password": SMTP_PASSWORD,
                "session_count": session_count,
                "user_count": users.len()
            }))
        }
        _ => HttpResponse::Forbidden().json(serde_json::json!({"error": "Admin access required"})),
    }
}

async fn debug_user(req: HttpRequest, path: web::Path<u32>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let user_id = path.into_inner();
    let users = state.users.lock().unwrap();
    match users.get(&user_id) {
        Some(user) => HttpResponse::Ok().json(user),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy", "service": "design-api"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        users: Mutex::new({
            let mut m = HashMap::new();
            m.insert(1, User { id: 1, username: "admin".into(), email: "admin@acmecorp.io".into(),
                password: "Adm1n_Pr0d!".into(), role: "admin".into(), active: true, failed_attempts: 0 });
            m.insert(2, User { id: 2, username: "jdoe".into(), email: "jdoe@acmecorp.io".into(),
                password: "JohnD_2024".into(), role: "manager".into(), active: true, failed_attempts: 0 });
            m.insert(3, User { id: 3, username: "asmith".into(), email: "asmith@acmecorp.io".into(),
                password: "alice_pass".into(), role: "developer".into(), active: true, failed_attempts: 0 });
            m.insert(4, User { id: 4, username: "bwilson".into(), email: "bwilson@acmecorp.io".into(),
                password: "B0b_W1ls0n".into(), role: "analyst".into(), active: false, failed_attempts: 0 });
            m
        }),
        sessions: Mutex::new(HashMap::new()),
        reset_tokens: Mutex::new(HashMap::new()),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/api/login", web::post().to(login))
            .route("/api/register", web::post().to(register))
            .route("/api/password-reset", web::post().to(request_password_reset))
            .route("/api/password-reset/confirm", web::post().to(confirm_password_reset))
            .route("/api/users/me", web::get().to(get_current_user))
            .route("/api/users/me/password", web::put().to(change_password))
            .route("/api/reports/generate", web::post().to(generate_report))
            .route("/api/config", web::get().to(get_config))
            .route("/api/debug/user/{id}", web::get().to(debug_user))
            .route("/api/health", web::get().to(health_check))
    })
    .bind("0.0.0.0:8097")?
    .run()
    .await
}
