use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
struct User {
    id: u32,
    username: String,
    email: String,
    role: String,
    ssn: String,
    salary: u64,
    department: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Order {
    id: u32,
    customer_id: u32,
    product: String,
    amount: f64,
    status: String,
    shipping_address: String,
    payment_method: String,
}

struct Session {
    user_id: u32,
    role: String,
}

struct AppState {
    users: Mutex<HashMap<u32, User>>,
    orders: Mutex<HashMap<u32, Order>>,
    sessions: HashMap<String, Session>,
}

fn get_session<'a>(req: &HttpRequest, state: &'a AppState) -> Option<&'a Session> {
    let auth = req.headers().get("Authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    state.sessions.get(token)
}

async fn get_user_profile(
    path: web::Path<u32>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let user_id = path.into_inner();
    let users = state.users.lock().unwrap();
    match users.get(&user_id) {
        Some(user) => HttpResponse::Ok().json(user),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

async fn get_order(
    req: HttpRequest,
    path: web::Path<u32>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let _session = match get_session(&req, &state) {
        Some(s) => s,
        None => return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Authentication required"})),
    };

    let order_id = path.into_inner();
    let orders = state.orders.lock().unwrap();
    match orders.get(&order_id) {
        Some(order) => HttpResponse::Ok().json(order),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Order not found"})),
    }
}

#[derive(Deserialize)]
struct UpdateOrder {
    product: Option<String>,
    amount: Option<f64>,
    status: Option<String>,
    shipping_address: Option<String>,
}

async fn update_order(
    req: HttpRequest,
    path: web::Path<u32>,
    body: web::Json<UpdateOrder>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let _session = match get_session(&req, &state) {
        Some(s) => s,
        None => return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Authentication required"})),
    };

    let order_id = path.into_inner();
    let mut orders = state.orders.lock().unwrap();
    let order = match orders.get_mut(&order_id) {
        Some(o) => o,
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Order not found"})),
    };

    if let Some(ref product) = body.product {
        order.product = product.clone();
    }
    if let Some(amount) = body.amount {
        order.amount = amount;
    }
    if let Some(ref status) = body.status {
        order.status = status.clone();
    }
    if let Some(ref addr) = body.shipping_address {
        order.shipping_address = addr.clone();
    }

    HttpResponse::Ok().json(serde_json::json!({"message": "Order updated", "order": order}))
}

async fn list_all_users(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let _session = match get_session(&req, &state) {
        Some(s) => s,
        None => return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Authentication required"})),
    };

    let client_role = req.headers()
        .get("X-User-Role")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if client_role != "admin" {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "Admin access required"}));
    }

    let users = state.users.lock().unwrap();
    let user_list: Vec<&User> = users.values().collect();
    HttpResponse::Ok().json(serde_json::json!({"users": user_list}))
}

#[derive(Deserialize)]
struct RoleUpdate {
    role: Option<String>,
}

async fn update_user_role(
    req: HttpRequest,
    path: web::Path<u32>,
    body: web::Json<RoleUpdate>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let _session = match get_session(&req, &state) {
        Some(s) => s,
        None => return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Authentication required"})),
    };

    let user_id = path.into_inner();
    let mut users = state.users.lock().unwrap();
    let user = match users.get_mut(&user_id) {
        Some(u) => u,
        None => return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "User not found"})),
    };

    let new_role = body.role.clone().unwrap_or_else(|| "customer".to_string());
    user.role = new_role.clone();

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Role updated",
        "userId": user_id,
        "newRole": new_role
    }))
}

async fn debug_config() -> HttpResponse {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://admin:s3cret@db:5432/orderdb".to_string());
    let secret = std::env::var("APP_SECRET")
        .unwrap_or_else(|_| "actix-secret-key-production".to_string());

    HttpResponse::Ok().json(serde_json::json!({
        "databaseUrl": db_url,
        "appSecret": secret,
        "apiKeys": {
            "stripe": std::env::var("STRIPE_KEY").unwrap_or_else(|_| "sk_live_stripe_key_123".to_string()),
            "sendgrid": std::env::var("SENDGRID_KEY").unwrap_or_else(|_| "SG.sendgrid_key_456".to_string()),
        },
        "rustVersion": "1.70",
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut users_map = HashMap::new();
    users_map.insert(1, User { id: 1, username: "alice".into(), email: "alice@shop.io".into(),
        role: "admin".into(), ssn: "123-45-6789".into(), salary: 145000, department: "operations".into() });
    users_map.insert(2, User { id: 2, username: "bob".into(), email: "bob@shop.io".into(),
        role: "support".into(), ssn: "987-65-4321".into(), salary: 78000, department: "support".into() });
    users_map.insert(3, User { id: 3, username: "charlie".into(), email: "charlie@shop.io".into(),
        role: "customer".into(), ssn: "555-12-3456".into(), salary: 0, department: "".into() });
    users_map.insert(4, User { id: 4, username: "diana".into(), email: "diana@shop.io".into(),
        role: "customer".into(), ssn: "444-33-2211".into(), salary: 0, department: "".into() });

    let mut orders_map = HashMap::new();
    orders_map.insert(401, Order { id: 401, customer_id: 3, product: "Laptop Pro 15".into(),
        amount: 1299.99, status: "shipped".into(), shipping_address: "123 Main St".into(),
        payment_method: "visa-4242".into() });
    orders_map.insert(402, Order { id: 402, customer_id: 4, product: "Wireless Mouse".into(),
        amount: 49.99, status: "processing".into(), shipping_address: "456 Oak Ave".into(),
        payment_method: "mastercard-5555".into() });
    orders_map.insert(403, Order { id: 403, customer_id: 3, product: "USB-C Hub".into(),
        amount: 79.99, status: "delivered".into(), shipping_address: "123 Main St".into(),
        payment_method: "visa-4242".into() });

    let mut sessions_map = HashMap::new();
    sessions_map.insert("tok_alice".to_string(), Session { user_id: 1, role: "admin".into() });
    sessions_map.insert("tok_bob".to_string(), Session { user_id: 2, role: "support".into() });
    sessions_map.insert("tok_charlie".to_string(), Session { user_id: 3, role: "customer".into() });
    sessions_map.insert("tok_diana".to_string(), Session { user_id: 4, role: "customer".into() });

    let data = web::Data::new(AppState {
        users: Mutex::new(users_map),
        orders: Mutex::new(orders_map),
        sessions: sessions_map,
    });

    println!("Order Management API running on port 8089");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/api/users/{user_id}", web::get().to(get_user_profile))
            .route("/api/orders/{order_id}", web::get().to(get_order))
            .route("/api/orders/{order_id}", web::put().to(update_order))
            .route("/api/admin/users", web::get().to(list_all_users))
            .route("/api/users/{user_id}/role", web::put().to(update_user_role))
            .route("/api/debug/config", web::get().to(debug_config))
    })
    .bind("0.0.0.0:8089")?
    .run()
    .await
}
