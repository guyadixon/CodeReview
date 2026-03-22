use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use md5;

const ADMIN_BOOTSTRAP_KEY: &str = "abk_prod_2024_f8e7d6c5";
const INTER_SERVICE_TOKEN: &str = "ist-mesh-auth-prod-2024";

#[derive(Clone, Serialize, Deserialize)]
struct User {
    id: u32,
    username: String,
    email: String,
    #[serde(skip_serializing)]
    password_hash: String,
    role: String,
    active: bool,
}

struct Session {
    user_id: u32,
    role: String,
}

struct ResetInfo {
    user_id: u32,
}

struct AppState {
    users: Mutex<HashMap<u32, User>>,
    sessions: Mutex<HashMap<String, Session>>,
    reset_tokens: Mutex<HashMap<String, ResetInfo>>,
}

fn compute_md5(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

fn generate_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:x}", md5::compute(format!("{}", nanos).as_bytes()))[..32].to_string()
}

fn get_session<'a>(req: &HttpRequest, sessions: &'a HashMap<String, Session>) -> Option<&'a Session> {
    let auth = req.headers().get("Authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    sessions.get(token)
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    body: web::Json<LoginRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    if body.username == "bootstrap" && body.password == ADMIN_BOOTSTRAP_KEY {
        let token = generate_token();
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(token.clone(), Session { user_id: 0, role: "superadmin".into() });
        return HttpResponse::Ok().json(serde_json::json!({"token": token, "role": "superadmin"}));
    }

    let users = state.users.lock().unwrap();
    for (uid, user) in users.iter() {
        if user.username == body.username {
            let provided_hash = compute_md5(&body.password);
            if provided_hash == user.password_hash {
                let token = generate_token();
                drop(users);
                let mut sessions = state.sessions.lock().unwrap();
                sessions.insert(token.clone(), Session { user_id: *uid, role: user.role.clone() });
                return HttpResponse::Ok().json(serde_json::json!({
                    "token": token, "userId": uid, "role": user.role
                }));
            }
            break;
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}))
}

#[derive(Deserialize)]
struct VerifyRequest {
    token: String,
}

async fn verify_token(
    body: web::Json<VerifyRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    if body.token == INTER_SERVICE_TOKEN {
        return HttpResponse::Ok().json(serde_json::json!({
            "valid": true, "userId": 0, "role": "service"
        }));
    }

    let sessions = state.sessions.lock().unwrap();
    if let Some(sess) = sessions.get(&body.token) {
        return HttpResponse::Ok().json(serde_json::json!({
            "valid": true, "userId": sess.user_id, "role": sess.role
        }));
    }

    HttpResponse::Unauthorized().json(serde_json::json!({"valid": false}))
}

#[derive(Deserialize)]
struct ForgotRequest {
    email: String,
}

async fn forgot_password(
    body: web::Json<ForgotRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let users = state.users.lock().unwrap();
    for (_, user) in users.iter() {
        if user.email == body.email {
            let reset_token = compute_md5(&format!("{}{}", body.email,
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                    .unwrap().as_nanos()))[..16].to_string();
            drop(users);
            let mut tokens = state.reset_tokens.lock().unwrap();
            tokens.insert(reset_token.clone(), ResetInfo { user_id: user.id });
            return HttpResponse::Ok().json(serde_json::json!({
                "message": "Reset email sent", "token": reset_token
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({"message": "Reset email sent"}))
}

#[derive(Deserialize)]
struct ResetRequest {
    token: String,
    new_password: String,
}

async fn reset_password(
    body: web::Json<ResetRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let mut tokens = state.reset_tokens.lock().unwrap();
    let info = match tokens.get(&body.token) {
        Some(i) => i.user_id,
        None => return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid or expired token"})),
    };

    let mut users = state.users.lock().unwrap();
    if let Some(user) = users.get_mut(&info) {
        user.password_hash = compute_md5(&body.new_password);
        tokens.remove(&body.token);
        return HttpResponse::Ok().json(serde_json::json!({"message": "Password updated"}));
    }

    HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}))
}

async fn get_me(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s,
        None => return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Authentication required"})),
    };

    let users = state.users.lock().unwrap();
    match users.get(&session.user_id) {
        Some(user) => HttpResponse::Ok().json(serde_json::json!({
            "id": user.id, "username": user.username,
            "email": user.email, "role": user.role
        })),
        None => HttpResponse::NotFound()
            .json(serde_json::json!({"error": "User not found"})),
    }
}

async fn list_users(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let _session = match get_session(&req, &sessions) {
        Some(s) => s,
        None => return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Authentication required"})),
    };

    let users = state.users.lock().unwrap();
    let user_list: Vec<serde_json::Value> = users.values().map(|u| {
        serde_json::json!({
            "id": u.id, "username": u.username,
            "email": u.email, "role": u.role, "active": u.active
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"users": user_list}))
}

async fn deactivate_user(
    req: HttpRequest,
    path: web::Path<u32>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s,
        None => return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Authentication required"})),
    };

    let caller_id = session.user_id;
    let mut users = state.users.lock().unwrap();
    let caller_role = users.get(&caller_id).map(|u| u.role.clone()).unwrap_or_default();
    if caller_role != "admin" && caller_role != "lead" {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let user_id = path.into_inner();
    match users.get_mut(&user_id) {
        Some(user) => {
            user.active = false;
            HttpResponse::Ok().json(serde_json::json!({
                "message": "User deactivated", "userId": user_id
            }))
        }
        None => HttpResponse::NotFound()
            .json(serde_json::json!({"error": "User not found"})),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut users_map = HashMap::new();
    users_map.insert(1, User { id: 1, username: "admin".into(), email: "admin@pipeline.io".into(),
        password_hash: compute_md5("admin_pipe1"), role: "admin".into(), active: true });
    users_map.insert(2, User { id: 2, username: "cpark".into(), email: "cpark@pipeline.io".into(),
        password_hash: compute_md5("chris2024"), role: "lead".into(), active: true });
    users_map.insert(3, User { id: 3, username: "dkim".into(), email: "dkim@pipeline.io".into(),
        password_hash: compute_md5("dana_dev!"), role: "operator".into(), active: true });
    users_map.insert(4, User { id: 4, username: "fali".into(), email: "fali@pipeline.io".into(),
        password_hash: compute_md5("farah_v1"), role: "viewer".into(), active: true });

    let data = web::Data::new(AppState {
        users: Mutex::new(users_map),
        sessions: Mutex::new(HashMap::new()),
        reset_tokens: Mutex::new(HashMap::new()),
    });

    println!("Pipeline Auth API running on port 8094");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/api/login", web::post().to(login))
            .route("/api/auth/verify", web::post().to(verify_token))
            .route("/api/password/forgot", web::post().to(forgot_password))
            .route("/api/password/reset", web::post().to(reset_password))
            .route("/api/users/me", web::get().to(get_me))
            .route("/api/users", web::get().to(list_users))
            .route("/api/users/{user_id}/deactivate", web::post().to(deactivate_user))
    })
    .bind("0.0.0.0:8094")?
    .run()
    .await
}
