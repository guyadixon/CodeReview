package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

type Post struct {
	ID        int64     `json:"id"`
	Author    string    `json:"author"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	Tags      string    `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

type Comment struct {
	ID        int64     `json:"id"`
	PostID    int64     `json:"post_id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

type UserProfile struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Bio         string `json:"bio"`
	Website     string `json:"website"`
}

var (
	postStore    = make(map[int64]*Post)
	commentStore = make(map[int64][]*Comment)
	profileStore = make(map[string]*UserProfile)
	postIDSeq    int64
	commentIDSeq int64
	mu           sync.RWMutex
)

func nextPostID() int64 {
	return atomic.AddInt64(&postIDSeq, 1)
}

func nextCommentID() int64 {
	return atomic.AddInt64(&commentIDSeq, 1)
}

const pageHeader = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>TechBoard</title>
<style>
body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
.post { border: 1px solid #e0e0e0; padding: 16px; margin: 12px 0; border-radius: 6px; }
.comment { background: #fafafa; padding: 10px; margin: 6px 0; border-left: 3px solid #4a90d9; }
nav { background: #1a1a2e; padding: 12px 20px; margin-bottom: 20px; border-radius: 6px; }
nav a { color: #e0e0e0; margin-right: 18px; text-decoration: none; }
form input, form textarea { display: block; margin: 6px 0; padding: 10px; width: 100%; box-sizing: border-box; }
form button { padding: 10px 20px; margin-top: 10px; cursor: pointer; background: #1a1a2e; color: white; border: none; border-radius: 4px; }
.tag { display: inline-block; background: #e8f0fe; color: #1a73e8; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin: 2px; }
</style></head><body>
<nav><a href="/">Home</a><a href="/new">New Post</a><a href="/search">Search</a><a href="/profile">Profile</a></nav>`

const pageFooter = `</body></html>`

func init() {
	p := &Post{
		ID:        nextPostID(),
		Author:    "admin",
		Title:     "Welcome to TechBoard",
		Content:   "A place for developers to share ideas and discuss technology.",
		Tags:      "welcome,meta",
		CreatedAt: time.Now(),
	}
	postStore[p.ID] = p
}

func indexPage(c *gin.Context) {
	tag := c.Query("tag")

	mu.RLock()
	defer mu.RUnlock()

	var buf strings.Builder
	buf.WriteString(pageHeader)
	buf.WriteString("<h1>TechBoard</h1>")

	if tag != "" {
		buf.WriteString(fmt.Sprintf("<p>Filtering by tag: <strong>%s</strong></p>", tag))
	}

	for _, post := range postStore {
		if tag != "" && !strings.Contains(post.Tags, tag) {
			continue
		}
		buf.WriteString(`<div class="post">`)
		buf.WriteString(fmt.Sprintf(`<h2><a href="/post/%d">%s</a></h2>`, post.ID, post.Title))
		buf.WriteString(fmt.Sprintf("<p>by <strong>%s</strong> on %s</p>", post.Author, post.CreatedAt.Format("2006-01-02 15:04")))

		if post.Tags != "" {
			for _, t := range strings.Split(post.Tags, ",") {
				t = strings.TrimSpace(t)
				buf.WriteString(fmt.Sprintf(`<span class="tag">%s</span>`, t))
			}
		}

		preview := post.Content
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		buf.WriteString(fmt.Sprintf("<p>%s</p>", preview))
		buf.WriteString("</div>")
	}

	buf.WriteString(pageFooter)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(buf.String()))
}

func viewPost(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.Data(http.StatusBadRequest, "text/html", []byte(pageHeader+"<h1>Invalid post ID</h1>"+pageFooter))
		return
	}

	mu.RLock()
	post, exists := postStore[id]
	comments := commentStore[id]
	mu.RUnlock()

	if !exists {
		c.Data(http.StatusNotFound, "text/html", []byte(pageHeader+"<h1>Post not found</h1>"+pageFooter))
		return
	}

	var buf strings.Builder
	buf.WriteString(pageHeader)
	buf.WriteString(fmt.Sprintf("<h1>%s</h1>", post.Title))
	buf.WriteString(fmt.Sprintf("<p>by <strong>%s</strong> on %s</p>", post.Author, post.CreatedAt.Format("2006-01-02 15:04")))

	if post.Tags != "" {
		for _, t := range strings.Split(post.Tags, ",") {
			t = strings.TrimSpace(t)
			buf.WriteString(fmt.Sprintf(`<span class="tag">%s</span>`, t))
		}
	}

	buf.WriteString(fmt.Sprintf(`<div style="margin: 20px 0; line-height: 1.6;">%s</div>`, post.Content))

	buf.WriteString(fmt.Sprintf("<h3>Comments (%d)</h3>", len(comments)))
	for _, cm := range comments {
		buf.WriteString(`<div class="comment">`)
		buf.WriteString(fmt.Sprintf("<strong>%s</strong>", cm.Author))
		buf.WriteString(fmt.Sprintf(" <small>%s</small>", cm.CreatedAt.Format("2006-01-02 15:04")))
		buf.WriteString(fmt.Sprintf("<p>%s</p>", cm.Body))
		buf.WriteString("</div>")
	}

	buf.WriteString(fmt.Sprintf(`
		<h3>Add Comment</h3>
		<form method="POST" action="/post/%d/comment">
			<input type="text" name="author" placeholder="Your name" required>
			<textarea name="body" placeholder="Your comment..." rows="4" required></textarea>
			<button type="submit">Post Comment</button>
		</form>`, id))

	buf.WriteString(pageFooter)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(buf.String()))
}

func addComment(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	author := c.PostForm("author")
	body := c.PostForm("body")

	cm := &Comment{
		ID:        nextCommentID(),
		PostID:    id,
		Author:    author,
		Body:      body,
		CreatedAt: time.Now(),
	}

	mu.Lock()
	commentStore[id] = append(commentStore[id], cm)
	mu.Unlock()

	c.Redirect(http.StatusFound, fmt.Sprintf("/post/%d", id))
}

func newPostPage(c *gin.Context) {
	page := pageHeader + `
		<h1>Create New Post</h1>
		<form method="POST" action="/new">
			<input type="text" name="author" placeholder="Author" required>
			<input type="text" name="title" placeholder="Title" required>
			<input type="text" name="tags" placeholder="Tags (comma-separated)">
			<textarea name="content" placeholder="Write your post..." rows="10" required></textarea>
			<button type="submit">Publish</button>
		</form>` + pageFooter
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

func createPost(c *gin.Context) {
	author := c.PostForm("author")
	title := c.PostForm("title")
	content := c.PostForm("content")
	tags := c.PostForm("tags")

	post := &Post{
		ID:        nextPostID(),
		Author:    author,
		Title:     title,
		Content:   content,
		Tags:      tags,
		CreatedAt: time.Now(),
	}

	mu.Lock()
	postStore[post.ID] = post
	mu.Unlock()

	c.Redirect(http.StatusFound, fmt.Sprintf("/post/%d", post.ID))
}

func searchPage(c *gin.Context) {
	q := c.Query("q")

	var buf strings.Builder
	buf.WriteString(pageHeader)
	buf.WriteString("<h1>Search</h1>")
	buf.WriteString(fmt.Sprintf(`
		<form method="GET" action="/search">
			<input type="text" name="q" placeholder="Search posts..." value="%s">
			<button type="submit">Search</button>
		</form>`, q))

	if q != "" {
		buf.WriteString(fmt.Sprintf("<h2>Results for: %s</h2>", q))

		mu.RLock()
		for _, post := range postStore {
			if strings.Contains(strings.ToLower(post.Title), strings.ToLower(q)) ||
				strings.Contains(strings.ToLower(post.Content), strings.ToLower(q)) {
				buf.WriteString(`<div class="post">`)
				highlighted := strings.ReplaceAll(post.Title, q, "<mark>"+q+"</mark>")
				buf.WriteString(fmt.Sprintf(`<h3><a href="/post/%d">%s</a></h3>`, post.ID, highlighted))
				preview := post.Content
				if len(preview) > 150 {
					preview = preview[:150] + "..."
				}
				buf.WriteString(fmt.Sprintf("<p>%s</p>", html.EscapeString(preview)))
				buf.WriteString("</div>")
			}
		}
		mu.RUnlock()
	}

	buf.WriteString(pageFooter)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(buf.String()))
}

func profilePage(c *gin.Context) {
	username, _ := c.Cookie("tb_user")

	if username != "" {
		mu.RLock()
		profile, exists := profileStore[username]
		mu.RUnlock()

		if exists {
			var buf strings.Builder
			buf.WriteString(pageHeader)
			buf.WriteString(fmt.Sprintf("<h1>%s</h1>", profile.DisplayName))
			buf.WriteString(fmt.Sprintf("<div><strong>Bio:</strong> %s</div>", profile.Bio))
			buf.WriteString(fmt.Sprintf(`<div><strong>Website:</strong> <a href="%s">%s</a></div>`, profile.Website, profile.Website))
			buf.WriteString("<br><a href='/profile/edit'>Edit Profile</a>")
			buf.WriteString(pageFooter)
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(buf.String()))
			return
		}
	}

	page := pageHeader + `
		<h1>Create Profile</h1>
		<form method="POST" action="/profile">
			<input type="text" name="username" placeholder="Username" required>
			<input type="text" name="display_name" placeholder="Display Name">
			<textarea name="bio" placeholder="About you" rows="3"></textarea>
			<input type="text" name="website" placeholder="Website URL">
			<button type="submit">Save</button>
		</form>` + pageFooter
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

func saveProfile(c *gin.Context) {
	username := c.PostForm("username")
	displayName := c.PostForm("display_name")
	if displayName == "" {
		displayName = username
	}
	bio := c.PostForm("bio")
	website := c.PostForm("website")

	profile := &UserProfile{
		Username:    username,
		DisplayName: displayName,
		Bio:         bio,
		Website:     website,
	}

	mu.Lock()
	profileStore[username] = profile
	mu.Unlock()

	c.SetCookie("tb_user", username, 86400, "/", "", false, false)
	c.Redirect(http.StatusFound, "/profile")
}

func errorPage(c *gin.Context) {
	msg := c.Query("msg")
	if msg == "" {
		msg = "An unexpected error occurred"
	}
	page := pageHeader + fmt.Sprintf("<h1>Error</h1><div style='color:red;'><p>%s</p></div><a href='/'>Go Home</a>", msg) + pageFooter
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

func apiPosts(c *gin.Context) {
	callback := c.Query("callback")

	mu.RLock()
	items := make([]map[string]interface{}, 0, len(postStore))
	for _, p := range postStore {
		items = append(items, map[string]interface{}{
			"id":     p.ID,
			"title":  p.Title,
			"author": p.Author,
		})
	}
	mu.RUnlock()

	data, _ := json.Marshal(items)

	if callback != "" {
		c.Data(http.StatusOK, "application/javascript", []byte(fmt.Sprintf("%s(%s)", callback, string(data))))
		return
	}

	c.Data(http.StatusOK, "application/json", data)
}

func main() {
	r := gin.Default()

	r.GET("/", indexPage)
	r.GET("/post/:id", viewPost)
	r.POST("/post/:id/comment", addComment)
	r.GET("/new", newPostPage)
	r.POST("/new", createPost)
	r.GET("/search", searchPage)
	r.GET("/profile", profilePage)
	r.POST("/profile", saveProfile)
	r.GET("/error", errorPage)
	r.GET("/api/posts", apiPosts)

	r.Run(":8085")
}
