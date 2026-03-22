use actix_web::{web, App, HttpServer, HttpResponse, middleware};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Deserialize)]
struct PingQuery {
    host: Option<String>,
}

#[derive(Deserialize)]
struct DnsQuery {
    domain: Option<String>,
    #[serde(rename = "type", default = "default_record_type")]
    record_type: String,
}

fn default_record_type() -> String {
    "A".to_string()
}

#[derive(Deserialize)]
struct LogSearchQuery {
    keyword: Option<String>,
    file: Option<String>,
    lines: Option<String>,
}

#[derive(Deserialize)]
struct FileListQuery {
    path: Option<String>,
    pattern: Option<String>,
}

#[derive(Deserialize)]
struct ArchiveRequest {
    path: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct PortCheckRequest {
    host: String,
    port: u16,
}

#[derive(Deserialize)]
struct CertCheckRequest {
    hostname: String,
    port: Option<u16>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct PingResponse {
    host: String,
    output: String,
}

#[derive(Serialize)]
struct DnsResponse {
    domain: String,
    #[serde(rename = "type")]
    record_type: String,
    result: String,
}

async fn ping_host(query: web::Query<PingQuery>) -> HttpResponse {
    let host = match &query.host {
        Some(h) if !h.is_empty() => h.clone(),
        _ => return HttpResponse::BadRequest().json(ErrorResponse {
            error: "host parameter is required".to_string(),
        }),
    };

    let cmd = format!("ping -c 3 {}", host);
    match Command::new("sh").arg("-c").arg(&cmd).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            HttpResponse::Ok().json(PingResponse { host, output: stdout })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
        }),
    }
}

fn run_dig(domain: &str, record_type: &str) -> String {
    let cmd = format!("dig {} {} +short", record_type, domain);
    match Command::new("sh").arg("-c").arg(&cmd).output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

async fn dns_lookup(query: web::Query<DnsQuery>) -> HttpResponse {
    let domain = match &query.domain {
        Some(d) if !d.is_empty() => d.clone(),
        _ => return HttpResponse::BadRequest().json(ErrorResponse {
            error: "domain parameter is required".to_string(),
        }),
    };

    let allowed_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
    let record_type = if allowed_types.contains(&query.record_type.as_str()) {
        query.record_type.clone()
    } else {
        "A".to_string()
    };

    let result = run_dig(&domain, &record_type);
    HttpResponse::Ok().json(DnsResponse {
        domain,
        record_type,
        result,
    })
}

async fn search_logs(query: web::Query<LogSearchQuery>) -> HttpResponse {
    let keyword = match &query.keyword {
        Some(k) if !k.is_empty() => k.clone(),
        _ => return HttpResponse::BadRequest().json(ErrorResponse {
            error: "keyword parameter is required".to_string(),
        }),
    };

    let log_file = query.file.clone().unwrap_or_else(|| "syslog".to_string());
    let lines = query.lines.clone().unwrap_or_else(|| "100".to_string());
    let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "/var/log/sysadmin".to_string());
    let log_path = format!("{}/{}", log_dir, log_file);

    let cmd = format!("tail -n {} {} | grep '{}'", lines, log_path, keyword);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let matches: Vec<&str> = if stdout.is_empty() {
                vec![]
            } else {
                stdout.split('\n').collect()
            };
            HttpResponse::Ok().json(serde_json::json!({
                "file": log_file,
                "matches": matches
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
        }),
    }
}

async fn list_files(query: web::Query<FileListQuery>) -> HttpResponse {
    let upload_dir = std::env::var("UPLOAD_DIR").unwrap_or_else(|_| "/tmp/uploads".to_string());
    let directory = query.path.clone().unwrap_or(upload_dir);
    let pattern = query.pattern.clone().unwrap_or_else(|| "*".to_string());

    match Command::new("find")
        .args([&directory, "-name", &pattern, "-maxdepth", "2"])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let files: Vec<&str> = if stdout.is_empty() {
                vec![]
            } else {
                stdout.split('\n').collect()
            };
            HttpResponse::Ok().json(serde_json::json!({
                "directory": directory,
                "files": files
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
        }),
    }
}

async fn archive_files(body: web::Json<ArchiveRequest>) -> HttpResponse {
    let archive_name = body.name.clone().unwrap_or_else(|| "archive".to_string());
    let safe_name = archive_name.replace('/', "_").replace('\\', "_");
    let archive_path = format!("/tmp/{}.tar.gz", safe_name);

    let cmd = format!("tar czf {} {}", archive_path, body.path);
    match Command::new("sh").arg("-c").arg(&cmd).output() {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "archive": archive_path })),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
        }),
    }
}

async fn check_port(body: web::Json<PortCheckRequest>) -> HttpResponse {
    if body.port < 1 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid port range".to_string(),
        });
    }

    let cmd = format!("nc -zv -w 3 {} {}", body.host, body.port);
    match Command::new("sh").arg("-c").arg(&cmd).output() {
        Ok(output) => {
            let result = String::from_utf8_lossy(&output.stderr).trim().to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "host": body.host,
                "port": body.port,
                "result": result
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
        }),
    }
}

async fn system_info() -> HttpResponse {
    let hostname = Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let uptime = Command::new("uptime")
        .arg("-p")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let kernel = Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    HttpResponse::Ok().json(serde_json::json!({
        "hostname": hostname,
        "uptime": uptime,
        "kernel": kernel
    }))
}

async fn check_cert(body: web::Json<CertCheckRequest>) -> HttpResponse {
    let port = body.port.unwrap_or(443);
    let cmd = format!(
        "echo | openssl s_client -connect {}:{} -servername {} 2>/dev/null | openssl x509 -noout -dates",
        body.hostname, port, body.hostname
    );

    match Command::new("sh").arg("-c").arg(&cmd).output() {
        Ok(output) => {
            let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "hostname": body.hostname,
                "port": port,
                "certificate": result
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
        }),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("SysAdmin API running on port 8083");
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .route("/api/ping", web::get().to(ping_host))
            .route("/api/dns/lookup", web::get().to(dns_lookup))
            .route("/api/logs/search", web::get().to(search_logs))
            .route("/api/files/list", web::get().to(list_files))
            .route("/api/files/archive", web::post().to(archive_files))
            .route("/api/network/check", web::post().to(check_port))
            .route("/api/system/info", web::get().to(system_info))
            .route("/api/certs/check", web::post().to(check_cert))
    })
    .bind("0.0.0.0:8083")?
    .run()
    .await
}
