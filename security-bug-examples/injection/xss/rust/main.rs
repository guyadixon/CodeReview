use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, middleware};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

static POST_SEQ: AtomicU64 = AtomicU64::new(0);
static COMMENT_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Serialize)]
struct Post {
    id: u64,
    author: String,
    title: String,
    content: String,
    created_at: String,
}

#[derive(Clone, Serialize)]
struct Comment {
    id: u64,
    post_id: u64,
    author: String,
    body: String,
    created_at: String,
}

#[derive(Clone, Serialize)]
struct Profile {
    username: String,
    display_name: String,
    bio: String,
    website: String,
}

struct AppState {
    posts: Mutex<HashMap<u64, Post>>,
    comments: Mutex<HashMap<u64, Vec<Comment>>>,
    profiles: Mutex<HashMap<String, Profile>>,
}

fn now_str() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    format!("{:02}:{:02} UTC", hours, mins)
}

const HEADER: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>RustForum</title>
<style>
body { font-family: monospace; max-width: 900px; margin: 0 auto; padding: 20px; background: #fefefe; }
.post { border: 1px solid #ddd; padding: 14px; margin: 10px 0; border-radius: 4px; }
.comment { background: #f4f4f4; padding: 10px; margin: 6px 0; border-left: 3px solid #e67e22; }
nav { background: #2d2d2d; padding: 10px 18px; margin-bottom: 20px; border-radius: 4px; }
nav a { color: #f0f0f0; margin-right: 16px; text-decoration: none; font-size: 14px; }
form input, form textarea { display: block; margin: 6px 0; padding: 8px; width: 100%; box-sizing: border-box; font-family: monospace; }
form button { padding: 8px 18px; margin-top: 8px; cursor: pointer; background: #2d2d2d; color: white; border: none; border-radius: 3px; }
</style></head><body>
<nav><a href="/">Home</a><a href="/new">New Thread</a><a href="/search">Search</a><a href="/profile">Profile</a></nav>"#;

const FOOTER: &str = "</body></html>";

async fn index(data: web::Data<AppState>) -> HttpResponse {
    let posts = data.posts.lock().unwrap();
    let mut page = String::from(HEADER);
    page.push_str("<h1>RustForum</h1>");

    let mut sorted: Vec<&Post> = posts.values().collect();
    sorted.sort_by(|a, b| b.id.cmp(&a.id));

    for post in sorted {
        page.push_str("<div class='post'>");
        page.push_str(&format!(
            "<h2><a href='/thread/{}'>{}</a></h2>",
            post.id, post.title
        ));
        page.push_str(&format!(
            "<p>by <strong>{}</strong> at {}</p>",
            post.author, post.created_at
        ));
        let preview = if post.content.len() > 200 {
            &post.content[..200]
        } else {
            &post.content
        };
        page.push_str(&format!("<p>{}</p>", preview));
        page.push_str("</div>");
    }

    page.push_str(FOOTER);
    HttpResponse::Ok().content_type("text/html").body(page)
}

async fn view_thread(data: web::Data<AppState>, path: web::Path<u64>) -> HttpResponse {
    let post_id = path.into_inner();
    let posts = data.posts.lock().unwrap();
    let comments = data.comments.lock().unwrap();

    let post = match posts.get(&post_id) {
        Some(p) => p.clone(),
        None => {
            return HttpResponse::NotFound()
                .content_type("text/html")
                .body(format!("{}<h1>Thread not found</h1>{}", HEADER, FOOTER));
        }
    };

    let post_comments = comments.get(&post_id).cloned().unwrap_or_default();
    drop(posts);
    drop(comments);

    let mut page = String::from(HEADER);
    page.push_str(&format!("<h1>{}</h1>", post.title));
    page.push_str(&format!(
        "<p>by <strong>{}</strong> at {}</p>",
        post.author, post.created_at
    ));
    page.push_str(&format!(
        "<div style='margin: 20px 0; line-height: 1.6;'>{}</div>",
        post.content
    ));

    page.push_str(&format!("<h3>Replies ({})</h3>", post_comments.len()));
    for cm in &post_comments {
        page.push_str("<div class='comment'>");
        page.push_str(&format!("<strong>{}</strong>", cm.author));
        page.push_str(&format!(" <small>{}</small>", cm.created_at));
        page.push_str(&format!("<p>{}</p>", cm.body));
        page.push_str("</div>");
    }

    page.push_str(&format!(
        r#"<h3>Reply</h3>
        <form method="POST" action="/thread/{}/reply">
            <input type="text" name="author" placeholder="Your name" required>
            <textarea name="body" placeholder="Your reply..." rows="4" required></textarea>
            <button type="submit">Post Reply</button>
        </form>"#,
        post_id
    ));

    page.push_str(FOOTER);
    HttpResponse::Ok().content_type("text/html").body(page)
}

#[derive(Deserialize)]
struct ReplyForm {
    author: String,
    body: String,
}

async fn add_reply(
    data: web::Data<AppState>,
    path: web::Path<u64>,
    form: web::Form<ReplyForm>,
) -> HttpResponse {
    let post_id = path.into_inner();
    let cm = Comment {
        id: COMMENT_SEQ.fetch_add(1, Ordering::SeqCst),
        post_id,
        author: form.author.clone(),
        body: form.body.clone(),
        created_at: now_str(),
    };

    let mut comments = data.comments.lock().unwrap();
    comments.entry(post_id).or_default().push(cm);

    HttpResponse::Found()
        .append_header(("Location", format!("/thread/{}", post_id)))
        .finish()
}

async fn new_thread_page() -> HttpResponse {
    let page = format!(
        r#"{}<h1>Start a New Thread</h1>
        <form method="POST" action="/new">
            <input type="text" name="author" placeholder="Author" required>
            <input type="text" name="title" placeholder="Thread title" required>
            <textarea name="content" placeholder="Write your post..." rows="10" required></textarea>
            <button type="submit">Create Thread</button>
        </form>{}"#,
        HEADER, FOOTER
    );
    HttpResponse::Ok().content_type("text/html").body(page)
}

#[derive(Deserialize)]
struct NewPostForm {
    author: String,
    title: String,
    content: String,
}

async fn create_thread(data: web::Data<AppState>, form: web::Form<NewPostForm>) -> HttpResponse {
    let post = Post {
        id: POST_SEQ.fetch_add(1, Ordering::SeqCst),
        author: form.author.clone(),
        title: form.title.clone(),
        content: form.content.clone(),
        created_at: now_str(),
    };

    let id = post.id;
    data.posts.lock().unwrap().insert(id, post);

    HttpResponse::Found()
        .append_header(("Location", format!("/thread/{}", id)))
        .finish()
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

async fn search_page(data: web::Data<AppState>, query: web::Query<SearchQuery>) -> HttpResponse {
    let q = query.q.clone().unwrap_or_default();

    let mut page = String::from(HEADER);
    page.push_str("<h1>Search</h1>");
    page.push_str(&format!(
        r#"<form method="GET" action="/search">
            <input type="text" name="q" placeholder="Search threads..." value="{}">
            <button type="submit">Search</button>
        </form>"#,
        q
    ));

    if !q.is_empty() {
        page.push_str(&format!("<h2>Results for: {}</h2>", q));

        let posts = data.posts.lock().unwrap();
        let lower_q = q.to_lowercase();
        for post in posts.values() {
            if post.title.to_lowercase().contains(&lower_q)
                || post.content.to_lowercase().contains(&lower_q)
            {
                page.push_str("<div class='post'>");
                let highlighted = post.title.replace(&q, &format!("<mark>{}</mark>", q));
                page.push_str(&format!(
                    "<h3><a href='/thread/{}'>{}</a></h3>",
                    post.id, highlighted
                ));
                let preview = if post.content.len() > 150 {
                    &post.content[..150]
                } else {
                    &post.content
                };
                page.push_str(&format!(
                    "<p>{}</p>",
                    preview.replace('<', "&lt;").replace('>', "&gt;")
                ));
                page.push_str("</div>");
            }
        }
    }

    page.push_str(FOOTER);
    HttpResponse::Ok().content_type("text/html").body(page)
}

async fn profile_page(data: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let username = req
        .cookie("rf_user")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if !username.is_empty() {
        let profiles = data.profiles.lock().unwrap();
        if let Some(profile) = profiles.get(&username) {
            let mut page = String::from(HEADER);
            page.push_str(&format!("<h1>{}</h1>", profile.display_name));
            page.push_str(&format!(
                "<div><strong>Bio:</strong> {}</div>",
                profile.bio
            ));
            page.push_str(&format!(
                "<div><strong>Website:</strong> <a href='{}'>{}</a></div>",
                profile.website, profile.website
            ));
            page.push_str(FOOTER);
            return HttpResponse::Ok().content_type("text/html").body(page);
        }
    }

    let page = format!(
        r#"{}<h1>Create Profile</h1>
        <form method="POST" action="/profile">
            <input type="text" name="username" placeholder="Username" required>
            <input type="text" name="display_name" placeholder="Display Name">
            <textarea name="bio" placeholder="About you" rows="3"></textarea>
            <input type="text" name="website" placeholder="Website URL">
            <button type="submit">Save</button>
        </form>{}"#,
        HEADER, FOOTER
    );
    HttpResponse::Ok().content_type("text/html").body(page)
}

#[derive(Deserialize)]
struct ProfileForm {
    username: String,
    display_name: Option<String>,
    bio: Option<String>,
    website: Option<String>,
}

async fn save_profile(data: web::Data<AppState>, form: web::Form<ProfileForm>) -> HttpResponse {
    let profile = Profile {
        username: form.username.clone(),
        display_name: form
            .display_name
            .clone()
            .unwrap_or_else(|| form.username.clone()),
        bio: form.bio.clone().unwrap_or_default(),
        website: form.website.clone().unwrap_or_default(),
    };

    data.profiles
        .lock()
        .unwrap()
        .insert(form.username.clone(), profile);

    HttpResponse::Found()
        .append_header(("Location", "/profile"))
        .cookie(
            actix_web::cookie::Cookie::build("rf_user", &form.username)
                .path("/")
                .max_age(actix_web::cookie::time::Duration::days(1))
                .finish(),
        )
        .finish()
}

#[derive(Deserialize)]
struct ErrorQuery {
    msg: Option<String>,
}

async fn error_page(query: web::Query<ErrorQuery>) -> HttpResponse {
    let msg = query
        .msg
        .clone()
        .unwrap_or_else(|| "An unexpected error occurred".to_string());
    let page = format!(
        "{}<h1>Error</h1><div style='color:red;'><p>{}</p></div><a href='/'>Go Home</a>{}",
        HEADER, msg, FOOTER
    );
    HttpResponse::Ok().content_type("text/html").body(page)
}

#[derive(Deserialize)]
struct CallbackQuery {
    callback: Option<String>,
}

async fn api_posts(data: web::Data<AppState>, query: web::Query<CallbackQuery>) -> HttpResponse {
    let posts = data.posts.lock().unwrap();
    let items: Vec<serde_json::Value> = posts
        .values()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "title": p.title,
                "author": p.author
            })
        })
        .collect();

    let json_data = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());

    if let Some(cb) = &query.callback {
        if !cb.is_empty() {
            return HttpResponse::Ok()
                .content_type("application/javascript")
                .body(format!("{}({})", cb, json_data));
        }
    }

    HttpResponse::Ok()
        .content_type("application/json")
        .body(json_data)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        posts: Mutex::new(HashMap::new()),
        comments: Mutex::new(HashMap::new()),
        profiles: Mutex::new(HashMap::new()),
    });

    {
        let seed = Post {
            id: POST_SEQ.fetch_add(1, Ordering::SeqCst),
            author: "admin".to_string(),
            title: "Welcome to RustForum".to_string(),
            content: "A discussion board built with Rust and Actix-web.".to_string(),
            created_at: now_str(),
        };
        state.posts.lock().unwrap().insert(seed.id, seed);
    }

    println!("RustForum running on port 8086");
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(middleware::Logger::default())
            .route("/", web::get().to(index))
            .route("/thread/{id}", web::get().to(view_thread))
            .route("/thread/{id}/reply", web::post().to(add_reply))
            .route("/new", web::get().to(new_thread_page))
            .route("/new", web::post().to(create_thread))
            .route("/search", web::get().to(search_page))
            .route("/profile", web::get().to(profile_page))
            .route("/profile", web::post().to(save_profile))
            .route("/error", web::get().to(error_page))
            .route("/api/posts", web::get().to(api_posts))
    })
    .bind("0.0.0.0:8086")?
    .run()
    .await
}
