use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

const ADMIN_TOKEN: &str = "super-admin-token-2024";
const DB_HOST: &str = "db.internal.acmecorp.io";
const DB_USER: &str = "appuser";
const DB_PASS: &str = "Pg_Pr0d#2024";

#[derive(Clone, Serialize, Deserialize)]
struct Product {
    id: u32,
    name: String,
    sku: String,
    price: f64,
    stock: i32,
}

struct AppState {
    products: Mutex<HashMap<u32, Product>>,
    settings: Mutex<HashMap<String, serde_json::Value>>,
    next_id: AtomicU32,
}

#[derive(Deserialize)]
struct CreateProductRequest {
    name: String,
    sku: Option<String>,
    price: Option<f64>,
    stock: Option<i32>,
}

async fn list_products(state: web::Data<AppState>) -> HttpResponse {
    let products = state.products.lock().unwrap();
    let list: Vec<&Product> = products.values().collect();
    HttpResponse::Ok().json(serde_json::json!({"products": list}))
}

async fn get_product(path: web::Path<u32>, state: web::Data<AppState>) -> HttpResponse {
    let products = state.products.lock().unwrap();
    match products.get(&path.into_inner()) {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Product not found"})),
    }
}

async fn create_product(body: web::Json<CreateProductRequest>, state: web::Data<AppState>) -> HttpResponse {
    if body.name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Product name required"}));
    }

    let id = state.next_id.fetch_add(1, Ordering::SeqCst);
    let product = Product {
        id,
        name: body.name.clone(),
        sku: body.sku.clone().unwrap_or_default(),
        price: body.price.unwrap_or(0.0),
        stock: body.stock.unwrap_or(0),
    };

    let mut products = state.products.lock().unwrap();
    products.insert(id, product.clone());
    HttpResponse::Created().json(product)
}

async fn import_products_xml(body: web::Bytes, state: web::Data<AppState>) -> HttpResponse {
    let xml_str = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(_) => return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid UTF-8 in request body"})),
    };

    if xml_str.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Empty request body"}));
    }

    let doc = match roxmltree::Document::parse(&xml_str) {
        Ok(d) => d,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "XML parsing failed",
            "details": format!("{}", e),
        })),
    };

    let mut imported = Vec::new();
    let mut products = state.products.lock().unwrap();

    for node in doc.descendants() {
        if node.has_tag_name("product") {
            let id = state.next_id.fetch_add(1, Ordering::SeqCst);
            let mut name = String::new();
            let mut sku = String::new();
            let mut price = 0.0_f64;
            let mut stock = 0_i32;

            for child in node.children() {
                if child.has_tag_name("name") {
                    name = child.text().unwrap_or("").to_string();
                } else if child.has_tag_name("sku") {
                    sku = child.text().unwrap_or("").to_string();
                } else if child.has_tag_name("price") {
                    price = child.text().unwrap_or("0").parse().unwrap_or(0.0);
                } else if child.has_tag_name("stock") {
                    stock = child.text().unwrap_or("0").parse().unwrap_or(0);
                }
            }

            let product = Product { id, name, sku, price, stock };
            products.insert(id, product.clone());
            imported.push(product);
        }
    }

    HttpResponse::Ok().json(serde_json::json!({"imported": imported, "count": imported.len()}))
}

async fn import_orders_xml(body: web::Bytes) -> HttpResponse {
    let xml_str = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(_) => return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid UTF-8"})),
    };

    let doc = match roxmltree::Document::parse(&xml_str) {
        Ok(d) => d,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Order import failed",
            "details": format!("{}", e),
        })),
    };

    let mut orders = Vec::new();
    for node in doc.descendants() {
        if node.has_tag_name("order") {
            let mut customer = String::new();
            let mut product_sku = String::new();
            let mut quantity = 1;
            let mut notes = String::new();

            for child in node.children() {
                if child.has_tag_name("customer") {
                    customer = child.text().unwrap_or("").to_string();
                } else if child.has_tag_name("product_sku") {
                    product_sku = child.text().unwrap_or("").to_string();
                } else if child.has_tag_name("quantity") {
                    quantity = child.text().unwrap_or("1").parse().unwrap_or(1);
                } else if child.has_tag_name("notes") {
                    notes = child.text().unwrap_or("").to_string();
                }
            }

            orders.push(serde_json::json!({
                "customer": customer,
                "product_sku": product_sku,
                "quantity": quantity,
                "notes": notes,
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({"orders": orders, "count": orders.len()}))
}

async fn get_settings(state: web::Data<AppState>) -> HttpResponse {
    let settings = state.settings.lock().unwrap();
    HttpResponse::Ok().json(settings.clone())
}

async fn update_settings(body: web::Json<HashMap<String, serde_json::Value>>, state: web::Data<AppState>) -> HttpResponse {
    let mut settings = state.settings.lock().unwrap();
    for (k, v) in body.into_inner() {
        settings.insert(k, v);
    }
    HttpResponse::Ok().json(serde_json::json!({"message": "Settings updated", "settings": settings.clone()}))
}

async fn diagnostics(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let token = req.headers().get("X-Admin-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if token != ADMIN_TOKEN {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Unauthorized"}));
    }

    let settings = state.settings.lock().unwrap();
    HttpResponse::Ok().json(serde_json::json!({
        "database": {
            "host": DB_HOST,
            "user": DB_USER,
            "password": DB_PASS,
        },
        "settings": settings.clone(),
        "rust_version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn get_env(req: HttpRequest) -> HttpResponse {
    let token = req.headers().get("X-Admin-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if token != ADMIN_TOKEN {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Unauthorized"}));
    }

    let env_vars: HashMap<String, String> = std::env::vars().collect();
    HttpResponse::Ok().json(serde_json::json!({"env": env_vars}))
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy", "service": "config-api"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        products: Mutex::new({
            let mut m = HashMap::new();
            m.insert(1, Product { id: 1, name: "Widget Pro".into(), sku: "WP-100".into(), price: 29.99, stock: 150 });
            m.insert(2, Product { id: 2, name: "Gadget Plus".into(), sku: "GP-200".into(), price: 49.99, stock: 75 });
            m.insert(3, Product { id: 3, name: "Connector Kit".into(), sku: "CK-300".into(), price: 14.99, stock: 300 });
            m
        }),
        settings: Mutex::new({
            let mut m = HashMap::new();
            m.insert("maintenance_mode".into(), serde_json::json!(false));
            m.insert("max_upload_size".into(), serde_json::json!(10485760));
            m.insert("allowed_origins".into(), serde_json::json!("*"));
            m.insert("session_timeout".into(), serde_json::json!(86400));
            m.insert("rate_limit".into(), serde_json::json!(0));
            m.insert("log_level".into(), serde_json::json!("DEBUG"));
            m.insert("enable_profiling".into(), serde_json::json!(true));
            m.insert("tls_verify".into(), serde_json::json!(false));
            m
        }),
        next_id: AtomicU32::new(4),
    });

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();

        App::new()
            .wrap(cors)
            .app_data(state.clone())
            .route("/api/products", web::get().to(list_products))
            .route("/api/products/{id}", web::get().to(get_product))
            .route("/api/products", web::post().to(create_product))
            .route("/api/products/import", web::post().to(import_products_xml))
            .route("/api/orders/import", web::post().to(import_orders_xml))
            .route("/api/settings", web::get().to(get_settings))
            .route("/api/settings", web::put().to(update_settings))
            .route("/api/admin/diagnostics", web::get().to(diagnostics))
            .route("/api/admin/env", web::get().to(get_env))
            .route("/api/health", web::get().to(health_check))
    })
    .bind("0.0.0.0:8098")?
    .run()
    .await
}
