use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const DES_KEY: [u8; 8] = *b"s3cr3t!!";
const SIGNING_SECRET: &str = "platform-sign-key-2024";

#[derive(Clone, Serialize, Deserialize)]
struct User {
    id: u32,
    username: String,
    email: String,
    #[serde(skip_serializing)]
    password_hash: String,
    role: String,
    active: bool,
    #[serde(skip_serializing)]
    hash_algo: String,
}

struct Session {
    user_id: u32,
}

struct EncryptedRecord {
    id: u32,
    encrypted_content: String,
    signature: String,
    owner_id: u32,
}

struct TokenInfo {
    label: String,
    owner_id: u32,
}

struct AppState {
    users: Mutex<HashMap<u32, User>>,
    sessions: Mutex<HashMap<String, Session>>,
    records: Mutex<HashMap<u32, EncryptedRecord>>,
    api_tokens: Mutex<HashMap<String, TokenInfo>>,
    record_counter: Mutex<u32>,
    token_seq: Mutex<u32>,
    rng_state: Mutex<u64>,
}

fn compute_md5(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

fn compute_sha1(input: &str) -> String {
    use sha1::{Sha1, Digest};
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

fn simple_prng_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state >> 33
}

fn generate_session_token(state: &AppState, user_id: u32) -> String {
    let mut rng = state.rng_state.lock().unwrap();
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut token = String::with_capacity(32);
    for _ in 0..32 {
        let idx = simple_prng_next(&mut rng) as usize % chars.len();
        token.push(chars[idx] as char);
    }
    drop(rng);
    let mut sessions = state.sessions.lock().unwrap();
    sessions.insert(token.clone(), Session { user_id });
    token
}

fn generate_api_token(state: &AppState) -> String {
    let mut seq = state.token_seq.lock().unwrap();
    *seq += 1;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let raw = format!("tkn-{}-{}", *seq, ts);
    compute_sha1(&raw)[..24].to_string()
}

fn pkcs5_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(padding as u8).take(padding));
    padded
}

fn pkcs5_unpad(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }
    let padding = *data.last().unwrap() as usize;
    data[..data.len() - padding].to_vec()
}

fn des_encrypt_ecb(plaintext: &str) -> String {
    use des::cipher::{BlockEncrypt, KeyInit};
    use des::Des;

    let cipher = Des::new_from_slice(&DES_KEY).unwrap();
    let padded = pkcs5_pad(plaintext.as_bytes(), 8);
    let mut encrypted = padded.clone();
    for chunk in encrypted.chunks_mut(8) {
        let block = des::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    base64::encode(&encrypted)
}

fn des_decrypt_ecb(ciphertext: &str) -> Result<String, String> {
    use des::cipher::{BlockDecrypt, KeyInit};
    use des::Des;

    let data = base64::decode(ciphertext).map_err(|e| e.to_string())?;
    let cipher = Des::new_from_slice(&DES_KEY).unwrap();
    let mut decrypted = data.clone();
    for chunk in decrypted.chunks_mut(8) {
        let block = des::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    let unpadded = pkcs5_unpad(&decrypted);
    String::from_utf8(unpadded).map_err(|e| e.to_string())
}

fn compute_signature(data: &str) -> String {
    compute_md5(&format!("{}{}", data, SIGNING_SECRET))
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

async fn login(body: web::Json<LoginRequest>, state: web::Data<AppState>) -> HttpResponse {
    let users = state.users.lock().unwrap();
    for (uid, user) in users.iter() {
        if user.username == body.username {
            let provided_hash = if user.hash_algo == "sha1" {
                compute_sha1(&body.password)
            } else {
                compute_md5(&body.password)
            };
            if provided_hash == user.password_hash {
                let role = user.role.clone();
                let id = *uid;
                drop(users);
                let token = generate_session_token(&state, id);
                return HttpResponse::Ok().json(serde_json::json!({
                    "token": token, "userId": id, "role": role
                }));
            }
            break;
        }
    }
    HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}))
}

#[derive(Deserialize)]
struct RecordRequest {
    content: String,
}

async fn create_record(req: HttpRequest, body: web::Json<RecordRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.user_id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let mut counter = state.record_counter.lock().unwrap();
    *counter += 1;
    let id = *counter;
    drop(counter);

    let encrypted = des_encrypt_ecb(&body.content);
    let sig = compute_signature(&body.content);

    let mut records = state.records.lock().unwrap();
    records.insert(id, EncryptedRecord {
        id, encrypted_content: encrypted, signature: sig.clone(), owner_id: session,
    });

    HttpResponse::Ok().json(serde_json::json!({
        "id": id, "signature": sig, "message": "Record encrypted and stored"
    }))
}

async fn get_record(req: HttpRequest, path: web::Path<u32>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let record_id = path.into_inner();
    let records = state.records.lock().unwrap();
    let record = match records.get(&record_id) {
        Some(r) => r,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "Record not found"})),
    };

    match des_decrypt_ecb(&record.encrypted_content) {
        Ok(decrypted) => HttpResponse::Ok().json(serde_json::json!({
            "id": record.id, "content": decrypted,
            "signature": record.signature, "ownerId": record.owner_id
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({"error": "Decryption failed"})),
    }
}

#[derive(Deserialize)]
struct TokenRequest {
    label: Option<String>,
}

async fn generate_token(req: HttpRequest, body: web::Json<TokenRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.user_id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let label = body.label.clone().unwrap_or_else(|| "default".to_string());
    let token = generate_api_token(&state);

    let mut tokens = state.api_tokens.lock().unwrap();
    tokens.insert(token.clone(), TokenInfo { label: label.clone(), owner_id: session });

    HttpResponse::Ok().json(serde_json::json!({"token": token, "label": label}))
}

#[derive(Deserialize)]
struct ValidateRequest {
    token: String,
}

async fn validate_token(body: web::Json<ValidateRequest>, state: web::Data<AppState>) -> HttpResponse {
    let tokens = state.api_tokens.lock().unwrap();
    if let Some(info) = tokens.get(&body.token) {
        return HttpResponse::Ok().json(serde_json::json!({
            "valid": true, "label": info.label, "ownerId": info.owner_id
        }));
    }
    HttpResponse::Unauthorized().json(serde_json::json!({"valid": false}))
}

#[derive(Deserialize)]
struct HashRequest {
    value: String,
    algorithm: Option<String>,
}

async fn hash_data(body: web::Json<HashRequest>) -> HttpResponse {
    let algo = body.algorithm.clone().unwrap_or_else(|| "md5".to_string());
    let result = if algo == "sha1" {
        compute_sha1(&body.value)
    } else {
        compute_md5(&body.value)
    };
    HttpResponse::Ok().json(serde_json::json!({"hash": result, "algorithm": algo}))
}

#[derive(Deserialize)]
struct EncryptRequest {
    plaintext: String,
}

async fn encrypt_data(body: web::Json<EncryptRequest>) -> HttpResponse {
    let encrypted = des_encrypt_ecb(&body.plaintext);
    HttpResponse::Ok().json(serde_json::json!({"ciphertext": encrypted}))
}

#[derive(Deserialize)]
struct DecryptRequest {
    ciphertext: String,
}

async fn decrypt_data(req: HttpRequest, body: web::Json<DecryptRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    match des_decrypt_ecb(&body.ciphertext) {
        Ok(decrypted) => HttpResponse::Ok().json(serde_json::json!({"plaintext": decrypted})),
        Err(_) => HttpResponse::BadRequest().json(serde_json::json!({"error": "Decryption failed"})),
    }
}

async fn list_users(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    if get_session(&req, &sessions).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
    }
    drop(sessions);

    let users = state.users.lock().unwrap();
    let user_list: Vec<serde_json::Value> = users.values().map(|u| {
        serde_json::json!({
            "id": u.id, "username": u.username, "email": u.email,
            "role": u.role, "active": u.active
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"users": user_list}))
}

#[derive(Deserialize)]
struct PasswordRequest {
    #[serde(rename = "newPassword")]
    new_password: String,
}

async fn change_password(req: HttpRequest, body: web::Json<PasswordRequest>, state: web::Data<AppState>) -> HttpResponse {
    let sessions = state.sessions.lock().unwrap();
    let session = match get_session(&req, &sessions) {
        Some(s) => s.user_id,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"})),
    };
    drop(sessions);

    let mut users = state.users.lock().unwrap();
    match users.get_mut(&session) {
        Some(user) => {
            user.password_hash = compute_md5(&body.new_password);
            HttpResponse::Ok().json(serde_json::json!({"message": "Password updated"}))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut users_map = HashMap::new();
    users_map.insert(1, User { id: 1, username: "admin".into(), email: "admin@ironlock.io".into(),
        password_hash: compute_md5("admin2024!"), role: "admin".into(), active: true, hash_algo: "md5".into() });
    users_map.insert(2, User { id: 2, username: "cmorris".into(), email: "cmorris@ironlock.io".into(),
        password_hash: compute_md5("chris_m99"), role: "manager".into(), active: true, hash_algo: "md5".into() });
    users_map.insert(3, User { id: 3, username: "alee".into(), email: "alee@ironlock.io".into(),
        password_hash: compute_sha1("amy_lee!"), role: "analyst".into(), active: true, hash_algo: "sha1".into() });
    users_map.insert(4, User { id: 4, username: "dkim".into(), email: "dkim@ironlock.io".into(),
        password_hash: compute_md5("dan_view"), role: "viewer".into(), active: false, hash_algo: "md5".into() });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let data = web::Data::new(AppState {
        users: Mutex::new(users_map),
        sessions: Mutex::new(HashMap::new()),
        records: Mutex::new(HashMap::new()),
        api_tokens: Mutex::new(HashMap::new()),
        record_counter: Mutex::new(0),
        token_seq: Mutex::new(1000),
        rng_state: Mutex::new(nanos),
    });

    println!("IronLock Crypto API running on port 8099");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/api/login", web::post().to(login))
            .route("/api/records", web::post().to(create_record))
            .route("/api/records/{id}", web::get().to(get_record))
            .route("/api/tokens/generate", web::post().to(generate_token))
            .route("/api/tokens/validate", web::post().to(validate_token))
            .route("/api/hash", web::post().to(hash_data))
            .route("/api/encrypt", web::post().to(encrypt_data))
            .route("/api/decrypt", web::post().to(decrypt_data))
            .route("/api/users", web::get().to(list_users))
            .route("/api/users/me/password", web::put().to(change_password))
    })
    .bind("0.0.0.0:8099")?
    .run()
    .await
}
