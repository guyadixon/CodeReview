# Security Companion Document: app.py

## Vulnerability: Direct String Concatenation in Product Search

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L62-L63  

### Description
The `search_products` function constructs a SQL query by directly concatenating the user-supplied `q` query parameter into a `LIKE` clause. The `keyword` variable is taken from `request.args.get("q", "")` and embedded into the SQL string without any sanitization or parameterization.

### Exploitation Scenario
An attacker sends a request such as `GET /api/products/search?q=' UNION SELECT id,username,email,membership_tier,0 FROM customers--`. The injected payload closes the `LIKE` string, appends a `UNION SELECT` to extract data from the `customers` table, and comments out the trailing `%'`. This allows the attacker to read arbitrary data from any table in the database.

### Remediation Guidance
Use parameterized queries with the `?` placeholder:
```python
query = "SELECT * FROM products WHERE name LIKE ?"
cursor = db.execute(query, ("%" + keyword + "%",))
```

### Complexity Rationale
This is rated Obvious because the user input flows directly from the request parameter into a string concatenation that builds a SQL query, with no intermediate processing or indirection.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the taint flow from `request.args.get()` to string concatenation in a SQL query is a textbook pattern that all major SAST tools flag reliably.

---

## Vulnerability: Format String SQL Injection in Order Filter Builder

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L70-L73  

### Description
The `build_order_filter` helper function constructs SQL `WHERE` clause fragments using Python's `str.format()` method with user-supplied filter values. The `status` parameter is embedded via `"status = '{}'".format(filters["status"])` and `min_quantity` via `"quantity >= {}".format(filters["min_quantity"])`. These formatted strings are later concatenated into the main query in `list_orders`.

### Exploitation Scenario
An attacker sends `GET /api/orders?customer_id=1&status=' OR '1'='1`. The `status` value is interpolated into the SQL fragment as `status = '' OR '1'='1'`, which evaluates to true for all rows. This bypasses the intended customer-scoped filter and returns all orders in the system. More destructive payloads could use stacked queries or subselects depending on the database driver configuration.

### Remediation Guidance
Return parameterized placeholders from the filter builder and collect values separately:
```python
def build_order_filter(filters):
    clauses = []
    params = []
    if "status" in filters:
        clauses.append("status = ?")
        params.append(filters["status"])
    if "min_quantity" in filters:
        clauses.append("quantity >= ?")
        params.append(filters["min_quantity"])
    return (" AND ".join(clauses) if clauses else "1=1"), params
```

### Complexity Rationale
This is rated Moderate because the vulnerability is split across two functions: the filter builder constructs the unsafe SQL fragments, and the caller in `list_orders` assembles them into the final query. A reviewer must trace the data flow through the helper function to identify the injection point.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to track the taint from `request.args` through the `filters` dictionary into `build_order_filter` and back into the SQL query. Tools that only analyze single functions may miss this.

---

## Vulnerability: ORDER BY Clause Injection via Unvalidated Sort Direction

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L112-L119  

### Description
The `list_products` function validates the `sort_by` column name against an allowlist but does not validate the `order` parameter. The `order` value from `request.args.get("order", "ASC")` is directly interpolated into the SQL query via `str.format()`. While the sort column is safe, the sort direction accepts arbitrary input that gets embedded into the `ORDER BY` clause.

### Exploitation Scenario
An attacker sends `GET /api/products?order=ASC;DROP TABLE products--` or uses a more subtle payload like `GET /api/products?order=ASC,(SELECT CASE WHEN (SELECT substr(username,1,1) FROM customers LIMIT 1)='a' THEN 1 ELSE 1/0 END)` to perform blind SQL injection through the ORDER BY clause. The attacker can extract data character by character using conditional errors or timing differences.

### Remediation Guidance
Validate the `order` parameter against an allowlist:
```python
allowed_orders = {"ASC", "DESC"}
if order.upper() not in allowed_orders:
    order = "ASC"
```
Or use parameterized ordering by mapping to known-safe values rather than interpolating user input.

### Complexity Rationale
This is rated Nuanced because the adjacent `sort_by` parameter is properly validated with an allowlist, which creates a false sense of security. A reviewer may assume the entire ORDER BY clause is safe after seeing the column validation, overlooking that the direction parameter is unvalidated.

### Detection Difficulty Rationale
This is rated Likely_Missed because ORDER BY injection through the sort direction is not a standard pattern in most SAST rule sets. The partial validation of the sort column may cause tools to consider the query safe, and the injection point is in a non-standard position within the SQL statement.

---

## Language Exclusions

The following languages are excluded from the SQL Injection (CWE-89) vulnerability class:

- **C and C++**: These languages rarely use SQL ORMs or database abstraction layers in typical application code. Database access in C and C++ is done through low-level driver APIs (e.g., libpq, mysql_real_query) that do not follow the same patterns as higher-level language frameworks, making SQL injection examples less representative of real-world vulnerable code.
- **Rust**: Rust's type system and the design of popular database crates (e.g., sqlx, diesel) strongly encourage parameterized queries at compile time. Producing a realistic SQL injection example in idiomatic Rust would require deliberately bypassing the safety guarantees that the ecosystem provides, resulting in contrived rather than representative code.
