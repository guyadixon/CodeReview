const express = require("express");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const posts = [];
const profiles = {};
let postIdSeq = 0;
let commentIdSeq = 0;

posts.push({
  id: ++postIdSeq,
  author: "admin",
  title: "Welcome to DevChat",
  content: "A community space for developers to share and discuss.",
  tags: "welcome,meta",
  comments: [],
  createdAt: new Date().toISOString(),
});

const HEADER = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>DevChat</title>
<style>
body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
.post { border: 1px solid #e0e0e0; padding: 16px; margin: 12px 0; border-radius: 6px; }
.comment { background: #f8f8f8; padding: 10px; margin: 6px 0; border-left: 3px solid #6c5ce7; }
nav { background: #2d3436; padding: 12px 20px; margin-bottom: 20px; border-radius: 6px; }
nav a { color: #dfe6e9; margin-right: 18px; text-decoration: none; }
form input, form textarea { display: block; margin: 6px 0; padding: 10px; width: 100%; box-sizing: border-box; }
form button { padding: 10px 20px; margin-top: 10px; cursor: pointer; background: #2d3436; color: white; border: none; border-radius: 4px; }
.tag { display: inline-block; background: #dfe6e9; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin: 2px; }
</style></head><body>
<nav><a href="/">Home</a><a href="/new">New Post</a><a href="/search">Search</a><a href="/profile">Profile</a></nav>`;

const FOOTER = `</body></html>`;

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

app.get("/", (req, res) => {
  const tag = req.query.tag || "";
  let page = HEADER + "<h1>DevChat</h1>";

  if (tag) {
    page += `<p>Filtering by tag: <strong>${tag}</strong></p>`;
  }

  const filtered = tag
    ? posts.filter((p) => p.tags && p.tags.includes(tag))
    : posts;

  const sorted = [...filtered].sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
  );

  for (const post of sorted) {
    page += `<div class="post">`;
    page += `<h2><a href="/post/${post.id}">${post.title}</a></h2>`;
    page += `<p>by <strong>${post.author}</strong> on ${post.createdAt}</p>`;
    if (post.tags) {
      post.tags.split(",").forEach((t) => {
        page += `<span class="tag">${t.trim()}</span>`;
      });
    }
    const preview =
      post.content.length > 200
        ? post.content.substring(0, 200) + "..."
        : post.content;
    page += `<p>${preview}</p>`;
    page += `</div>`;
  }

  if (sorted.length === 0) {
    page += "<p>No posts yet. <a href='/new'>Create one!</a></p>";
  }

  page += FOOTER;
  res.send(page);
});

app.get("/post/:id", (req, res) => {
  const post = posts.find((p) => p.id === parseInt(req.params.id));
  if (!post) {
    return res.status(404).send(HEADER + "<h1>Post not found</h1>" + FOOTER);
  }

  let page = HEADER;
  page += `<h1>${post.title}</h1>`;
  page += `<p>by <strong>${post.author}</strong> on ${post.createdAt}</p>`;
  if (post.tags) {
    post.tags.split(",").forEach((t) => {
      page += `<span class="tag">${t.trim()}</span>`;
    });
  }
  page += `<div style="margin: 20px 0; line-height: 1.6;">${post.content}</div>`;

  page += `<h3>Comments (${post.comments.length})</h3>`;
  for (const c of post.comments) {
    page += `<div class="comment">`;
    page += `<strong>${c.author}</strong>`;
    page += ` <small>${c.createdAt}</small>`;
    page += `<p>${c.body}</p>`;
    page += `</div>`;
  }

  page += `
    <h3>Add Comment</h3>
    <form method="POST" action="/post/${post.id}/comment">
      <input type="text" name="author" placeholder="Your name" required>
      <textarea name="body" placeholder="Your comment..." rows="4" required></textarea>
      <button type="submit">Post Comment</button>
    </form>`;

  page += FOOTER;
  res.send(page);
});

app.post("/post/:id/comment", (req, res) => {
  const post = posts.find((p) => p.id === parseInt(req.params.id));
  if (!post) {
    return res.redirect("/");
  }

  post.comments.push({
    id: ++commentIdSeq,
    author: req.body.author || "Anonymous",
    body: req.body.body || "",
    createdAt: new Date().toISOString(),
  });

  res.redirect(`/post/${post.id}`);
});

app.get("/new", (req, res) => {
  const page =
    HEADER +
    `<h1>Create New Post</h1>
    <form method="POST" action="/new">
      <input type="text" name="author" placeholder="Author" required>
      <input type="text" name="title" placeholder="Title" required>
      <input type="text" name="tags" placeholder="Tags (comma-separated)">
      <textarea name="content" placeholder="Write your post..." rows="10" required></textarea>
      <button type="submit">Publish</button>
    </form>` +
    FOOTER;
  res.send(page);
});

app.post("/new", (req, res) => {
  const post = {
    id: ++postIdSeq,
    author: req.body.author || "Anonymous",
    title: req.body.title || "Untitled",
    content: req.body.content || "",
    tags: req.body.tags || "",
    comments: [],
    createdAt: new Date().toISOString(),
  };
  posts.push(post);
  res.redirect(`/post/${post.id}`);
});

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  let page = HEADER + "<h1>Search</h1>";
  page += `
    <form method="GET" action="/search">
      <input type="text" name="q" placeholder="Search posts..." value="${q}">
      <button type="submit">Search</button>
    </form>`;

  if (q) {
    page += `<h2>Results for: ${q}</h2>`;
    const lower = q.toLowerCase();
    const results = posts.filter(
      (p) =>
        p.title.toLowerCase().includes(lower) ||
        p.content.toLowerCase().includes(lower)
    );

    for (const post of results) {
      page += `<div class="post">`;
      const highlighted = post.title.replace(
        new RegExp(q, "gi"),
        `<mark>${q}</mark>`
      );
      page += `<h3><a href="/post/${post.id}">${highlighted}</a></h3>`;
      const preview =
        post.content.length > 150
          ? post.content.substring(0, 150) + "..."
          : post.content;
      page += `<p>${escapeHtml(preview)}</p>`;
      page += `</div>`;
    }

    if (results.length === 0) {
      page += "<p>No results found.</p>";
    }
  }

  page += FOOTER;
  res.send(page);
});

app.get("/profile", (req, res) => {
  const username = req.cookies.dc_user || "";

  if (username && profiles[username]) {
    const profile = profiles[username];
    let page = HEADER;
    page += `<h1>${profile.displayName}</h1>`;
    page += `<div><strong>Bio:</strong> ${profile.bio}</div>`;
    page += `<div><strong>Website:</strong> <a href="${profile.website}">${profile.website}</a></div>`;
    page += `<br><a href="/profile/edit">Edit Profile</a>`;
    page += FOOTER;
    return res.send(page);
  }

  const page =
    HEADER +
    `<h1>Create Profile</h1>
    <form method="POST" action="/profile">
      <input type="text" name="username" placeholder="Username" required>
      <input type="text" name="display_name" placeholder="Display Name">
      <textarea name="bio" placeholder="About you" rows="3"></textarea>
      <input type="text" name="website" placeholder="Website URL">
      <button type="submit">Save</button>
    </form>` +
    FOOTER;
  res.send(page);
});

app.post("/profile", (req, res) => {
  const username = req.body.username;
  profiles[username] = {
    username,
    displayName: req.body.display_name || username,
    bio: req.body.bio || "",
    website: req.body.website || "",
  };
  res.cookie("dc_user", username, { maxAge: 86400000, path: "/" });
  res.redirect("/profile");
});

app.get("/error", (req, res) => {
  const msg = req.query.msg || "An unexpected error occurred";
  const page =
    HEADER +
    `<h1>Error</h1><div style="color:red;"><p>${msg}</p></div><a href="/">Go Home</a>` +
    FOOTER;
  res.send(page);
});

app.get("/api/posts", (req, res) => {
  const callback = req.query.callback;
  const data = posts.map((p) => ({
    id: p.id,
    title: p.title,
    author: p.author,
  }));

  if (callback) {
    const jsonp = `${callback}(${JSON.stringify(data)})`;
    res.set("Content-Type", "application/javascript");
    return res.send(jsonp);
  }

  res.json(data);
});

app.get("/embed", (req, res) => {
  const title = req.query.title || "Widget";
  const theme = req.query.theme || "light";
  const page = `<!DOCTYPE html>
<html><head><title>${escapeHtml(title)}</title></head>
<body class="${theme}">
<h2>${title}</h2>
<div id="content"></div>
<script>
  var config = { theme: "${theme}", title: "${title}" };
  document.getElementById("content").innerHTML = "<p>Loaded: " + config.title + "</p>";
</script>
</body></html>`;
  res.send(page);
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`DevChat running on port ${PORT}`);
});
