from flask import Flask, request, make_response, redirect, url_for
import html
import json
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = os.environ.get("DB_PATH", "/tmp/forum.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts(id)
        );
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            bio TEXT DEFAULT '',
            website TEXT DEFAULT ''
        );
    """)
    conn.commit()
    conn.close()


HEADER = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Community Forum</title>
<style>
body { font-family: sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
.post { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
.comment { background: #f9f9f9; padding: 10px; margin: 5px 0; border-left: 3px solid #ccc; }
nav { background: #333; padding: 10px; margin-bottom: 20px; border-radius: 5px; }
nav a { color: white; margin-right: 15px; text-decoration: none; }
form input, form textarea { display: block; margin: 5px 0; padding: 8px; width: 100%; box-sizing: border-box; }
form button { padding: 10px 20px; margin-top: 10px; cursor: pointer; }
.search-highlight { background: yellow; }
</style></head><body>
<nav><a href="/">Home</a><a href="/new">New Post</a><a href="/search">Search</a><a href="/profile">Profile</a></nav>
"""

FOOTER = "</body></html>"


@app.route("/")
def index():
    conn = get_db()
    posts = conn.execute(
        "SELECT * FROM posts ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    conn.close()

    page = HEADER + "<h1>Community Forum</h1>"
    for post in posts:
        page += '<div class="post">'
        page += "<h2>{}</h2>".format(post["title"])
        page += "<p>by <strong>{}</strong></p>".format(post["author"])
        page += "<p>{}</p>".format(post["content"][:200])
        page += '<a href="/post/{}">Read more</a>'.format(post["id"])
        page += "</div>"

    if not posts:
        page += "<p>No posts yet. <a href='/new'>Create one!</a></p>"

    page += FOOTER
    return page


@app.route("/post/<int:post_id>")
def view_post(post_id):
    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        conn.close()
        return "Post not found", 404

    comments = conn.execute(
        "SELECT * FROM comments WHERE post_id = ? ORDER BY created_at", (post_id,)
    ).fetchall()
    conn.close()

    page = HEADER
    page += "<h1>{}</h1>".format(post["title"])
    page += "<p>by <strong>{}</strong> on {}</p>".format(
        post["author"], post["created_at"]
    )
    page += "<div>{}</div>".format(post["content"])

    page += "<h3>Comments</h3>"
    for comment in comments:
        page += '<div class="comment">'
        page += "<strong>{}</strong>".format(comment["author"])
        page += "<p>{}</p>".format(comment["body"])
        page += "</div>"

    page += """
    <h3>Add a Comment</h3>
    <form method="POST" action="/post/{}/comment">
        <input type="text" name="author" placeholder="Your name" required>
        <textarea name="body" placeholder="Your comment" rows="3" required></textarea>
        <button type="submit">Post Comment</button>
    </form>""".format(post_id)

    page += FOOTER
    return page


@app.route("/post/<int:post_id>/comment", methods=["POST"])
def add_comment(post_id):
    author = request.form.get("author", "Anonymous")
    body = request.form.get("body", "")

    conn = get_db()
    conn.execute(
        "INSERT INTO comments (post_id, author, body) VALUES (?, ?, ?)",
        (post_id, author, body),
    )
    conn.commit()
    conn.close()
    return redirect("/post/{}".format(post_id))


@app.route("/new", methods=["GET", "POST"])
def new_post():
    if request.method == "POST":
        author = request.form.get("author", "Anonymous")
        title = request.form.get("title", "")
        content = request.form.get("content", "")

        conn = get_db()
        conn.execute(
            "INSERT INTO posts (author, title, content) VALUES (?, ?, ?)",
            (author, title, content),
        )
        conn.commit()
        conn.close()
        return redirect("/")

    page = HEADER + """
    <h1>Create New Post</h1>
    <form method="POST">
        <input type="text" name="author" placeholder="Author name" required>
        <input type="text" name="title" placeholder="Post title" required>
        <textarea name="content" placeholder="Post content" rows="10" required></textarea>
        <button type="submit">Publish</button>
    </form>""" + FOOTER
    return page


@app.route("/search")
def search():
    query = request.args.get("q", "")
    page = HEADER + "<h1>Search Posts</h1>"
    page += """
    <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search..." value="{}">
        <button type="submit">Search</button>
    </form>""".format(query)

    if query:
        page += "<p>Results for: <em>{}</em></p>".format(query)
        conn = get_db()
        posts = conn.execute(
            "SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?",
            ("%{}%".format(query), "%{}%".format(query)),
        ).fetchall()
        conn.close()

        for post in posts:
            page += '<div class="post">'
            highlighted_title = post["title"].replace(
                query, '<span class="search-highlight">{}</span>'.format(query)
            )
            page += "<h2>{}</h2>".format(highlighted_title)
            page += '<a href="/post/{}">View</a>'.format(post["id"])
            page += "</div>"

        if not posts:
            page += "<p>No results found.</p>"

    page += FOOTER
    return page


@app.route("/profile", methods=["GET", "POST"])
def profile():
    username = request.cookies.get("username", "")

    if request.method == "POST":
        username = request.form.get("username", "")
        display_name = request.form.get("display_name", username)
        bio = request.form.get("bio", "")
        website = request.form.get("website", "")

        conn = get_db()
        conn.execute(
            "INSERT OR REPLACE INTO profiles (username, display_name, bio, website) VALUES (?, ?, ?, ?)",
            (username, display_name, bio, website),
        )
        conn.commit()
        conn.close()

        resp = make_response(redirect("/profile"))
        resp.set_cookie("username", username)
        return resp

    if username:
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM profiles WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user:
            page = HEADER
            page += "<h1>Profile: {}</h1>".format(user["display_name"])
            page += "<div><strong>Bio:</strong> {}</div>".format(user["bio"])
            page += '<div><strong>Website:</strong> <a href="{}">{}</a></div>'.format(
                user["website"], user["website"]
            )
            page += FOOTER
            return page

    page = HEADER + """
    <h1>Edit Profile</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="text" name="display_name" placeholder="Display Name">
        <textarea name="bio" placeholder="Tell us about yourself" rows="4"></textarea>
        <input type="text" name="website" placeholder="Your website URL">
        <button type="submit">Save Profile</button>
    </form>""" + FOOTER
    return page


@app.route("/preview", methods=["POST"])
def preview_post():
    content = request.form.get("content", "")
    title = request.form.get("title", "Preview")

    page = HEADER
    page += "<h1>{}</h1>".format(html.escape(title))
    page += "<div>{}</div>".format(content)
    page += '<a href="/new">Back to editor</a>'
    page += FOOTER
    return page


@app.route("/error")
def error_page():
    message = request.args.get("msg", "An unknown error occurred")
    page = HEADER
    page += "<h1>Error</h1>"
    page += "<div class='error'><p>{}</p></div>".format(message)
    page += '<a href="/">Return to home</a>'
    page += FOOTER
    return page


@app.route("/api/posts")
def api_posts():
    callback = request.args.get("callback", "")
    conn = get_db()
    posts = conn.execute("SELECT id, author, title FROM posts ORDER BY created_at DESC LIMIT 10").fetchall()
    conn.close()

    data = json.dumps([dict(p) for p in posts])
    if callback:
        response = make_response("{}({})".format(callback, data))
        response.headers["Content-Type"] = "application/javascript"
        return response

    return data, 200, {"Content-Type": "application/json"}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5002, debug=False)
