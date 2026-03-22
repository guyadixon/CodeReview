use actix_web::{web, App, HttpServer, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
struct Product {
    id: u32,
    name: String,
    price: f64,
    stock: i32,
    category: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct OrderItem {
    product_id: u32,
    name: String,
    quantity: i32,
    subtotal: f64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Order {
    id: u32,
    items: Vec<OrderItem>,
    total: f64,
    status: String,
    customer_email: String,
}

struct AppState {
    products: Mutex<HashMap<u32, Product>>,
    orders: Mutex<HashMap<u32, Order>>,
    order_counter: Mutex<u32>,
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

async fn list_products(state: web::Data<AppState>, query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let products = state.products.lock().unwrap();
    let category = query.get("category");
    let result: Vec<&Product> = products.values()
        .filter(|p| category.map_or(true, |c| &p.category == c))
        .collect();
    HttpResponse::Ok().json(serde_json::json!({
        "products": result, "total": result.len()
    }))
}

async fn get_product(state: web::Data<AppState>, path: web::Path<u32>) -> HttpResponse {
    let products = state.products.lock().unwrap();
    match products.get(&path.into_inner()) {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Product not found"})),
    }
}

#[derive(Deserialize)]
struct CreateOrderRequest {
    items: Vec<CreateOrderItem>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct CreateOrderItem {
    product_id: u32,
    quantity: Option<i32>,
}

async fn create_order(state: web::Data<AppState>, body: web::Json<CreateOrderRequest>) -> HttpResponse {
    if body.items.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "At least one item required"}));
    }

    let mut products = state.products.lock().unwrap();
    let mut counter = state.order_counter.lock().unwrap();

    let mut order_items = Vec::new();
    let mut total = 0.0;

    for item in &body.items {
        let product = match products.get_mut(&item.product_id) {
            Some(p) => p,
            None => return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Product {} not found", item.product_id)
            })),
        };
        let qty = item.quantity.unwrap_or(1);
        if product.stock < qty {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Insufficient stock for {}", product.name)
            }));
        }
        product.stock -= qty;
        let subtotal = round2(product.price * qty as f64);
        total += subtotal;
        order_items.push(OrderItem {
            product_id: product.id,
            name: product.name.clone(),
            quantity: qty,
            subtotal,
        });
    }

    *counter += 1;
    let order_id = *counter;
    let order = Order {
        id: order_id,
        items: order_items,
        total: round2(total),
        status: "confirmed".to_string(),
        customer_email: body.email.clone().unwrap_or_default(),
    };

    let mut orders = state.orders.lock().unwrap();
    orders.insert(order_id, order);

    HttpResponse::Created().json(serde_json::json!({
        "order_id": order_id, "total": round2(total), "status": "confirmed"
    }))
}

async fn get_order(state: web::Data<AppState>, path: web::Path<u32>) -> HttpResponse {
    let orders = state.orders.lock().unwrap();
    match orders.get(&path.into_inner()) {
        Some(o) => HttpResponse::Ok().json(o),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Order not found"})),
    }
}

#[derive(Deserialize)]
struct ImportRequest {
    format: Option<String>,
    payload: serde_json::Value,
}

async fn import_inventory(state: web::Data<AppState>, body: web::Json<ImportRequest>) -> HttpResponse {
    let payload = &body.payload;

    let product_updates: Vec<serde_json::Value> = match payload.get("products") {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid payload format"})),
    };

    let mut products = state.products.lock().unwrap();
    let mut updated = 0;

    for entry in &product_updates {
        if let Some(id) = entry.get("id").and_then(|v| v.as_u64()) {
            if let Some(product) = products.get_mut(&(id as u32)) {
                if let Some(stock) = entry.get("stock").and_then(|v| v.as_i64()) {
                    product.stock = stock as i32;
                }
                if let Some(price) = entry.get("price").and_then(|v| v.as_f64()) {
                    product.price = price;
                }
                updated += 1;
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({"message": "Inventory updated", "updated_count": updated}))
}

async fn generate_label(state: web::Data<AppState>, path: web::Path<u32>) -> HttpResponse {
    let products = state.products.lock().unwrap();
    match products.get(&path.into_inner()) {
        Some(p) => {
            let label = format!("{} - ${:.2} [{}]", p.name, p.price, p.category);
            HttpResponse::Ok().json(serde_json::json!({"label": label, "product_id": p.id}))
        }
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Product not found"})),
    }
}

async fn warehouse_config() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "location": "us-east-1",
        "api_endpoint": "https://warehouse.internal.acmecorp.io/api/v2",
        "max_batch_size": 50,
        "retry_attempts": 3
    }))
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy", "service": "inventory-api"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        products: Mutex::new({
            let mut m = HashMap::new();
            m.insert(1, Product { id: 1, name: "Widget Pro".into(), price: 29.99, stock: 150, category: "hardware".into() });
            m.insert(2, Product { id: 2, name: "Gadget Plus".into(), price: 49.99, stock: 75, category: "electronics".into() });
            m.insert(3, Product { id: 3, name: "Tool Kit Standard".into(), price: 19.99, stock: 200, category: "tools".into() });
            m.insert(4, Product { id: 4, name: "Sensor Array".into(), price: 89.99, stock: 30, category: "electronics".into() });
            m.insert(5, Product { id: 5, name: "Cable Bundle".into(), price: 9.99, stock: 500, category: "accessories".into() });
            m
        }),
        orders: Mutex::new(HashMap::new()),
        order_counter: Mutex::new(1000),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/api/products", web::get().to(list_products))
            .route("/api/products/{id}", web::get().to(get_product))
            .route("/api/products/{id}/label", web::get().to(generate_label))
            .route("/api/orders", web::post().to(create_order))
            .route("/api/orders/{id}", web::get().to(get_order))
            .route("/api/inventory/import", web::post().to(import_inventory))
            .route("/api/config/warehouse", web::get().to(warehouse_config))
            .route("/api/health", web::get().to(health_check))
    })
    .bind("0.0.0.0:8110")?
    .run()
    .await
}
