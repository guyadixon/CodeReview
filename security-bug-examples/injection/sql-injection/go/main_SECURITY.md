# Security Companion Document: main.go

## Vulnerability: Direct String Concatenation in Product Search

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L53-L54  

### Description
The `searchProducts` handler constructs a SQL query by directly concatenating the `q` query parameter into a `LIKE` clause using the `+` operator. The `keyword` variable from `c.Query("q")` is embedded into the SQL string without any sanitization or parameterization.

### Exploitation Scenario
An attacker sends `GET /api/products/search?q=' UNION SELECT 1,'admin','secret','0.00',0--`. The injected payload closes the `LIKE` string, appends a `UNION SELECT` to return arbitrary data, and comments out the trailing SQL. This allows the attacker to extract data from any table accessible to the database connection.

### Remediation Guidance
Use parameterized queries with the `?` placeholder:
```go
query := "SELECT id, name, category, price, stock FROM products WHERE name LIKE ?"
rows, err := db.Query(query, "%"+keyword+"%")
```

### Complexity Rationale
This is rated Obvious because the user input flows directly from the Gin query parameter into string concatenation that builds a SQL query, with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the direct concatenation of a query parameter into a SQL string is a textbook pattern that all major SAST tools including gosec and Semgrep flag reliably.

---

## Vulnerability: Category Concatenation and ORDER BY Injection in Product Query Builder

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L83-L86  

### Description
The `buildProductQuery` helper function concatenates the `category` parameter directly into a SQL `WHERE` clause using string concatenation. Additionally, while the `sortCol` parameter is validated against an allowlist, the `sortDir` parameter is passed through `fmt.Sprintf` into the `ORDER BY` clause without validation, allowing injection through the sort direction.

### Exploitation Scenario
For the category injection: `GET /api/products?category=' OR '1'='1' UNION SELECT 1,username,email,membership_tier,0 FROM customers--`. The injected value breaks out of the WHERE clause and extracts data from other tables.

For the sort direction injection: `GET /api/products?order=ASC;DROP TABLE products--`. While SQLite may not support stacked queries in all drivers, blind injection via `GET /api/products?order=ASC,(CASE WHEN (SELECT length(username) FROM customers LIMIT 1)>3 THEN 1 ELSE 1/0 END)` can extract data through conditional errors.

### Remediation Guidance
Use parameterized queries for the category and validate the sort direction:
```go
allowedDirs := map[string]bool{"ASC": true, "DESC": true}
if !allowedDirs[strings.ToUpper(sortDir)] {
    sortDir = "ASC"
}
base := "SELECT id, name, category, price, stock FROM products"
if category != "" {
    base += " WHERE category = ?"
}
```

### Complexity Rationale
This is rated Moderate because the vulnerability is in a helper function that mixes safe patterns (column allowlist) with unsafe patterns (category concatenation, unvalidated sort direction). A reviewer must analyze the helper function separately from the calling handler.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools need interprocedural analysis to trace the taint from the Gin handler through the helper function. The column allowlist validation may cause some tools to consider the query partially safe.

---

## Vulnerability: Status Filter Concatenation in Order Listing

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L131-L133  

### Description
The `listOrders` handler constructs a SQL query where the `customer_id` is properly parameterized with a `?` placeholder, but the `status` query parameter is concatenated directly into the SQL string. The status value from `c.Query("status")` is embedded using string concatenation without sanitization.

### Exploitation Scenario
An attacker sends `GET /api/orders?customer_id=1&status=' OR '1'='1`. The status value is concatenated into the SQL as `AND o.status = '' OR '1'='1'`, which bypasses the customer filter and returns all orders. More advanced payloads can use subqueries to extract data from other tables.

### Remediation Guidance
Use parameterized placeholders for the status filter:
```go
if status := c.Query("status"); status != "" {
    query += " AND o.status = ?"
    args = append(args, status)
}
```

### Complexity Rationale
This is rated Moderate because the method mixes parameterized and non-parameterized query construction. The `customer_id` is safely parameterized, which may lead a reviewer to assume all parameters are handled similarly.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must distinguish between the parameterized base query and the concatenated filter values within the same function. Tools that track individual variables through conditional branches will detect this.

---

## Vulnerability: Tag-Based SQL Injection via Loop Concatenation

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Nuanced  
**Detection Difficulty:** Likely_Missed  
**Affected Lines:** L135-L140  

### Description
The `listOrders` handler accepts a `tags` query parameter, splits it by comma, and iterates over each tag to append `LIKE` clauses to the SQL query using `fmt.Sprintf`. Each tag value is embedded directly into the SQL string within the loop body without parameterization. The use of `strings.TrimSpace` provides only whitespace trimming, not SQL sanitization.

### Exploitation Scenario
An attacker sends `GET /api/orders?customer_id=1&tags=x%25' OR '1'='1'--%20`. The tag value is interpolated into the SQL via `Sprintf`, producing `AND p.name LIKE '%x%' OR '1'='1'--%'`. This breaks out of the LIKE clause and injects arbitrary SQL. Because the injection happens inside a loop, multiple injection points can be chained: `tags=a,b' UNION SELECT 1,2,3,4,5,6--`.

### Remediation Guidance
Use parameterized queries within the loop:
```go
if tags := c.Query("tags"); tags != "" {
    tagList := strings.Split(tags, ",")
    for _, tag := range tagList {
        query += " AND p.name LIKE ?"
        args = append(args, "%"+strings.TrimSpace(tag)+"%")
    }
}
```

### Complexity Rationale
This is rated Nuanced because the injection occurs inside a loop that processes a comma-separated input, adding a layer of indirection. The `strings.TrimSpace` call may give a false impression of input sanitization. The vulnerability requires understanding that the loop dynamically builds multiple SQL clauses from a single parameter.

### Detection Difficulty Rationale
This is rated Likely_Missed because the injection point is inside a loop body that processes split string values, which is an uncommon pattern for SAST rules. The combination of `strings.Split`, loop iteration, and `fmt.Sprintf` within a query builder creates a multi-step taint flow that many tools do not model.
