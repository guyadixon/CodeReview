package com.example.blog;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@SpringBootApplication
@Controller
public class App {

    private static final AtomicLong postIdGen = new AtomicLong(0);
    private static final AtomicLong commentIdGen = new AtomicLong(0);
    private static final Map<Long, BlogPost> posts = new ConcurrentHashMap<>();
    private static final Map<String, UserProfile> profiles = new ConcurrentHashMap<>();
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    static class BlogPost {
        long id;
        String author;
        String title;
        String content;
        String category;
        String createdAt;
        List<Comment> comments = new CopyOnWriteArrayList<>();
    }

    static class Comment {
        long id;
        String author;
        String body;
        String createdAt;
    }

    static class UserProfile {
        String username;
        String displayName;
        String bio;
        String website;
        String avatarUrl;
    }

    private static final String HEADER = """
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="UTF-8"><title>Dev Blog</title>
            <style>
            body { font-family: Georgia, serif; max-width: 960px; margin: 0 auto; padding: 20px; color: #333; }
            .post { border-bottom: 1px solid #eee; padding: 20px 0; }
            .comment { background: #f5f5f5; padding: 12px; margin: 8px 0; border-radius: 4px; }
            nav { background: #2c3e50; padding: 12px 20px; margin-bottom: 25px; border-radius: 4px; }
            nav a { color: #ecf0f1; margin-right: 20px; text-decoration: none; font-size: 14px; }
            form input, form textarea, form select { display: block; margin: 8px 0; padding: 10px; width: 100%%; box-sizing: border-box; }
            form button { padding: 10px 24px; margin-top: 12px; cursor: pointer; background: #2c3e50; color: white; border: none; border-radius: 4px; }
            .tag { display: inline-block; background: #e8e8e8; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin-right: 5px; }
            </style></head><body>
            <nav><a href="/">Home</a><a href="/write">Write</a><a href="/search">Search</a><a href="/profile">Profile</a></nav>
            """;

    private static final String FOOTER = "</body></html>";

    @PostConstruct
    public void seedData() {
        BlogPost sample = new BlogPost();
        sample.id = postIdGen.incrementAndGet();
        sample.author = "admin";
        sample.title = "Welcome to Dev Blog";
        sample.content = "This is a community blog for developers. Share your knowledge and experiences.";
        sample.category = "general";
        sample.createdAt = LocalDateTime.now().format(FMT);
        posts.put(sample.id, sample);
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String index(@RequestParam(required = false) String category) {
        StringBuilder page = new StringBuilder(HEADER);
        page.append("<h1>Dev Blog</h1>");

        if (category != null && !category.isEmpty()) {
            page.append("<p>Filtering by category: <strong>").append(category).append("</strong></p>");
        }

        List<BlogPost> sorted = new ArrayList<>(posts.values());
        sorted.sort((a, b) -> b.createdAt.compareTo(a.createdAt));

        for (BlogPost post : sorted) {
            if (category != null && !category.isEmpty() && !post.category.equalsIgnoreCase(category)) {
                continue;
            }
            page.append("<div class='post'>");
            page.append("<h2><a href='/post/").append(post.id).append("'>").append(post.title).append("</a></h2>");
            page.append("<p>by <strong>").append(post.author).append("</strong> on ").append(post.createdAt).append("</p>");
            if (post.category != null) {
                page.append("<span class='tag'>").append(post.category).append("</span>");
            }
            String preview = post.content.length() > 250 ? post.content.substring(0, 250) + "..." : post.content;
            page.append("<p>").append(preview).append("</p>");
            page.append("</div>");
        }

        page.append(FOOTER);
        return page.toString();
    }

    @GetMapping(value = "/post/{id}", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String viewPost(@PathVariable long id) {
        BlogPost post = posts.get(id);
        if (post == null) {
            return HEADER + "<h1>Post not found</h1>" + FOOTER;
        }

        StringBuilder page = new StringBuilder(HEADER);
        page.append("<h1>").append(post.title).append("</h1>");
        page.append("<p>by <strong>").append(post.author).append("</strong> on ").append(post.createdAt).append("</p>");
        if (post.category != null) {
            page.append("<span class='tag'>").append(post.category).append("</span>");
        }
        page.append("<div style='margin: 20px 0; line-height: 1.6;'>").append(post.content).append("</div>");

        page.append("<h3>Comments (").append(post.comments.size()).append(")</h3>");
        for (Comment c : post.comments) {
            page.append("<div class='comment'>");
            page.append("<strong>").append(c.author).append("</strong>");
            page.append(" <small>").append(c.createdAt).append("</small>");
            page.append("<p>").append(c.body).append("</p>");
            page.append("</div>");
        }

        page.append("""
            <h3>Leave a Comment</h3>
            <form method="POST" action="/post/%d/comment">
                <input type="text" name="author" placeholder="Your name" required>
                <textarea name="body" placeholder="Write your comment..." rows="4" required></textarea>
                <button type="submit">Submit</button>
            </form>
            """.formatted(id));

        page.append(FOOTER);
        return page.toString();
    }

    @PostMapping("/post/{id}/comment")
    public String addComment(@PathVariable long id,
                             @RequestParam String author,
                             @RequestParam String body) {
        BlogPost post = posts.get(id);
        if (post != null) {
            Comment c = new Comment();
            c.id = commentIdGen.incrementAndGet();
            c.author = author;
            c.body = body;
            c.createdAt = LocalDateTime.now().format(FMT);
            post.comments.add(c);
        }
        return "redirect:/post/" + id;
    }

    @GetMapping(value = "/write", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String writeForm() {
        return HEADER + """
            <h1>Write a Post</h1>
            <form method="POST" action="/write">
                <input type="text" name="author" placeholder="Author" required>
                <input type="text" name="title" placeholder="Title" required>
                <select name="category">
                    <option value="general">General</option>
                    <option value="tutorial">Tutorial</option>
                    <option value="news">News</option>
                    <option value="discussion">Discussion</option>
                </select>
                <textarea name="content" placeholder="Write your post (HTML supported)..." rows="12" required></textarea>
                <button type="submit">Publish</button>
            </form>
            """ + FOOTER;
    }

    @PostMapping("/write")
    public String createPost(@RequestParam String author,
                             @RequestParam String title,
                             @RequestParam String content,
                             @RequestParam(defaultValue = "general") String category) {
        BlogPost post = new BlogPost();
        post.id = postIdGen.incrementAndGet();
        post.author = author;
        post.title = title;
        post.content = content;
        post.category = category;
        post.createdAt = LocalDateTime.now().format(FMT);
        posts.put(post.id, post);
        return "redirect:/post/" + post.id;
    }

    @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String search(@RequestParam(required = false, defaultValue = "") String q) {
        StringBuilder page = new StringBuilder(HEADER);
        page.append("<h1>Search</h1>");
        page.append("""
            <form method="GET" action="/search">
                <input type="text" name="q" placeholder="Search posts..." value="%s">
                <button type="submit">Search</button>
            </form>
            """.formatted(q));

        if (!q.isEmpty()) {
            page.append("<h2>Results for: ").append(q).append("</h2>");
            String lower = q.toLowerCase();
            for (BlogPost post : posts.values()) {
                if (post.title.toLowerCase().contains(lower) || post.content.toLowerCase().contains(lower)) {
                    page.append("<div class='post'>");
                    String highlighted = post.title.replace(q,
                            "<mark>" + q + "</mark>");
                    page.append("<h3><a href='/post/").append(post.id).append("'>").append(highlighted).append("</a></h3>");
                    page.append("<p>").append(HtmlUtils.htmlEscape(post.content.substring(0, Math.min(150, post.content.length())))).append("...</p>");
                    page.append("</div>");
                }
            }
        }

        page.append(FOOTER);
        return page.toString();
    }

    @GetMapping(value = "/profile", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String profilePage(HttpServletRequest request) {
        String username = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("blog_user".equals(cookie.getName())) {
                    username = cookie.getValue();
                    break;
                }
            }
        }

        if (username != null && profiles.containsKey(username)) {
            UserProfile profile = profiles.get(username);
            StringBuilder page = new StringBuilder(HEADER);
            page.append("<h1>").append(profile.displayName).append("</h1>");
            page.append("<div><strong>Bio:</strong> ").append(profile.bio).append("</div>");
            page.append("<div><strong>Website:</strong> <a href='").append(profile.website).append("'>")
                    .append(profile.website).append("</a></div>");
            if (profile.avatarUrl != null && !profile.avatarUrl.isEmpty()) {
                page.append("<div><img src='").append(profile.avatarUrl).append("' width='100' alt='avatar'></div>");
            }
            page.append("<br><a href='/profile/edit'>Edit Profile</a>");
            page.append(FOOTER);
            return page.toString();
        }

        return HEADER + """
            <h1>Login / Register</h1>
            <form method="POST" action="/profile">
                <input type="text" name="username" placeholder="Username" required>
                <input type="text" name="display_name" placeholder="Display Name">
                <textarea name="bio" placeholder="About you" rows="3"></textarea>
                <input type="text" name="website" placeholder="Website URL">
                <input type="text" name="avatar_url" placeholder="Avatar image URL">
                <button type="submit">Save</button>
            </form>
            """ + FOOTER;
    }

    @PostMapping("/profile")
    public String saveProfile(@RequestParam String username,
                              @RequestParam(defaultValue = "") String display_name,
                              @RequestParam(defaultValue = "") String bio,
                              @RequestParam(defaultValue = "") String website,
                              @RequestParam(defaultValue = "") String avatar_url,
                              HttpServletResponse response) {
        UserProfile profile = new UserProfile();
        profile.username = username;
        profile.displayName = display_name.isEmpty() ? username : display_name;
        profile.bio = bio;
        profile.website = website;
        profile.avatarUrl = avatar_url;
        profiles.put(username, profile);

        Cookie cookie = new Cookie("blog_user", username);
        cookie.setPath("/");
        cookie.setMaxAge(86400);
        response.addCookie(cookie);

        return "redirect:/profile";
    }

    @GetMapping(value = "/error", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String errorPage(@RequestParam(defaultValue = "Something went wrong") String msg) {
        return HEADER + "<h1>Error</h1><div style='color:red;'><p>" + msg + "</p></div><a href='/'>Go Home</a>" + FOOTER;
    }

    @GetMapping(value = "/api/posts", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<String> apiPosts(@RequestParam(required = false) String callback) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (BlogPost post : posts.values()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("id", post.id);
            entry.put("title", post.title);
            entry.put("author", post.author);
            result.add(entry);
        }

        String json = result.toString();
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            json = mapper.writeValueAsString(result);
        } catch (Exception ignored) {}

        if (callback != null && !callback.isEmpty()) {
            String jsonp = callback + "(" + json + ")";
            return ResponseEntity.ok()
                    .header("Content-Type", "application/javascript")
                    .body(jsonp);
        }

        return ResponseEntity.ok().body(json);
    }

    public static void main(String[] args) {
        System.setProperty("server.port", "8084");
        SpringApplication.run(App.class, args);
    }
}
