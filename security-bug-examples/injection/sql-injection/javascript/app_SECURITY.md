# Security Companion Document: app.js

## Vulnerability: Template Literal SQL Injection in Product Search

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L37-L37  

### Description
The `/api/products/search` handler constructs a SQL query using a JavaScript template literal that embeds the `keyword` variable directly into a `LIKE` clause. The `keyword` value comes from `req.query.q` without any sanitization or parameterization.

### Exploitation Scenario
An attacker sends `GET /api/products/search?q=' UNION SELECT 1,'admin','secret',0.00,0--`. The injected payload closes the `LIKE` string, appends a `UNION SELECT` to return arbitrary data, and comments out the trailing SQL. This allows the attacker to extract data from any table in the SQLite database.

### Remediation Guidance
Use parameterized queries with the `?` placeholder:
```javascript
const sql = "SELECT * FROM products WHERE name LIKE ?";
const rows = db.prepare(sql).all("%" + keyword + "%");
```

### Complexity Rationale
This is rated Obvious because the user input flows directly from the query parameter into a template literal that builds a SQL query, with no intermediate processing or indirection.

### Detection Difficulty Rationale
This is rated Easily_Detectable because template literal interpolation of user input into a SQL string is a well-known pattern that SAST tools like eslint-plugin-security and Semgrep flag reliably.

---

## Vulnerability: Filter Status Concatenation via Helper Function

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L50-L52  

### Description
The `applyFilters` helper function constructs SQL `WHERE` clause fragments using template literals with user-supplied filter values. The `status` filter value is embedded directly into the SQL string as `o.status = '${filters.status}'`. These fragments are later concatenated into the main query used by the `/api/orders` handler.

### Exploitation Scenario
An attacker sends `GET /api/orders?customer_id=1&status=' OR '1'='1`. The status value is interpolated into the SQL fragment as `o.status = '' OR '1'='1'`, which evaluates to true for all rows. This bypasses the customer-scoped filter and returns all orders in the system.

### Remediation Guidance
Return parameterized placeholders from the filter function and collect values separately:
```javascript
function applyFilters(baseQuery, params, filters) {
  const clauses = [];
  const values = [...params];
  if (filters.status) {
    clauses.push("o.status = ?");
    values.push(filters.status);
  }
  // ...
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability is split across two code locations: the `applyFilters` helper constructs the unsafe SQL fragments, and the `/api/orders` handler assembles them into the final query. A reviewer must trace the data flow through the helper function.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to track the taint from `req.query` through the `filters` object into `applyFilters` and back into the SQL query. Tools that only analyze individual functions may miss this.

---

## Vulnerability: ORDER BY Clause Injection via Unvalidated Sort Direction

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L99-L102  

### Description
The `/api/products` handler validates the `sort` column name against an allowlist using a `Set`, but the `order` parameter (sort direction) is embedded directly into the SQL query via template literal without validation. The `order` value from `req.query` defaults to `"ASC"` but accepts arbitrary input that gets interpolated into the `ORDER BY` clause.

### Exploitation Scenario
An attacker sends `GET /api/products?order=ASC;DROP TABLE products--` or uses a blind injection payload like `GET /api/products?order=ASC,(SELECT CASE WHEN (SELECT length(username) FROM customers LIMIT 1)>3 THEN 1 ELSE 1/0 END)` to extract data through conditional errors in the ORDER BY clause.

### Remediation Guidance
Validate the `order` parameter against an allowlist:
```javascript
const allowedOrders = new Set(["ASC", "DESC"]);
const safeOrder = allowedOrders.has(order.toUpperCase()) ? order : "ASC";
```

### Complexity Rationale
This is rated Nuanced because the adjacent `sort` parameter is properly validated with an allowlist, creating a false sense of security. A reviewer may assume the entire ORDER BY clause is safe after seeing the column validation, overlooking that the direction parameter is unvalidated.

### Detection Difficulty Rationale
This is rated Likely_Missed because ORDER BY injection through the sort direction is not a standard pattern in most SAST rule sets. The partial validation of the sort column may cause tools to consider the query safe, and the injection point is in a non-standard position.

---

## Vulnerability: Column Injection and Category Concatenation in Reports Endpoint

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L155-L165  

### Description
The `/api/reports/products` handler accepts a `fields` query parameter that specifies which columns to select. The field names are split by comma, trimmed, and joined back into a string that is interpolated directly into the `SELECT` clause via template literal. Additionally, the `category` parameter is concatenated into a `WHERE` clause without parameterization. There is no validation that the field names correspond to actual column names.

### Exploitation Scenario
An attacker sends `GET /api/reports/products?fields=name,(SELECT email FROM customers LIMIT 1)` to inject a subquery into the SELECT clause, extracting data from other tables. The category parameter offers a second injection vector: `GET /api/reports/products?category=' UNION SELECT username,email FROM customers--`.

### Remediation Guidance
Validate field names against an allowlist and parameterize the category:
```javascript
const allowedFields = new Set(["id", "name", "category", "price", "stock"]);
const safeFields = fields.split(",")
  .map(f => f.trim())
  .filter(f => allowedFields.has(f));
const columnList = safeFields.length > 0 ? safeFields.join(", ") : "name, price";

let sql = `SELECT ${columnList} FROM products`;
if (category) {
  sql += " WHERE category = ?";
  rows = db.prepare(sql).all(category);
}
```

### Complexity Rationale
This is rated Nuanced because the injection occurs in the SELECT column list, which is an unusual injection point. The `split`, `map`, and `join` operations on the fields parameter create an appearance of input processing that may be mistaken for sanitization. The dual injection vectors (column list and category) add further complexity.

### Detection Difficulty Rationale
This is rated Likely_Missed because SELECT clause injection through dynamic column names is not a common pattern in SAST rule sets. The string processing pipeline (split, map, trim, join) obscures the direct taint flow, and many tools focus on WHERE clause injection rather than SELECT clause manipulation.
