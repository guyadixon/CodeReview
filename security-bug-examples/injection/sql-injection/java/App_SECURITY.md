# Security Companion Document: App.java

## Vulnerability: Direct String Concatenation in Product Search

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L57-L58  

### Description
The `searchProducts` method constructs a SQL query by directly concatenating the `q` request parameter into a `LIKE` clause. The user-supplied value is embedded into the SQL string without parameterization, then passed to `jdbc.queryForList()`.

### Exploitation Scenario
An attacker sends `GET /api/products/search?q=' UNION SELECT 1,username,email,membership_tier,0 FROM customers--`. The injected payload breaks out of the `LIKE` clause, appends a `UNION SELECT` to extract customer credentials, and comments out the trailing SQL. The attacker receives customer data in the product search response.

### Remediation Guidance
Use parameterized queries with JdbcTemplate:
```java
String sql = "SELECT * FROM products WHERE name LIKE ?";
List<Map<String, Object>> results = jdbc.queryForList(sql, "%" + q + "%");
```

### Complexity Rationale
This is rated Obvious because the user input flows directly from the `@RequestParam` annotation into string concatenation that builds a SQL query, with no intermediate processing.

### Detection Difficulty Rationale
This is rated Easily_Detectable because the direct concatenation of a request parameter into a SQL string is a textbook pattern recognized by all major SAST tools including SpotBugs and Semgrep.

---

## Vulnerability: String Concatenation in Product Listing with Category and ORDER BY

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L74-L79  

### Description
The `listProducts` method concatenates the `category` parameter directly into a SQL `WHERE` clause using string concatenation. While the `sort` column is validated against an allowlist, the `category` value and the `order` direction parameter are both embedded directly into the SQL string without sanitization.

### Exploitation Scenario
An attacker sends `GET /api/products?category=' OR '1'='1' UNION SELECT 1,username,email,membership_tier,0 FROM customers--`. The injected category value breaks out of the `WHERE` clause and appends a `UNION SELECT` to extract data from other tables. Alternatively, the `order` parameter can be exploited: `GET /api/products?order=ASC,(SELECT username FROM customers LIMIT 1)`.

### Remediation Guidance
Use parameterized queries for the category filter and validate the order direction:
```java
Set<String> allowedOrders = Set.of("ASC", "DESC");
String safeOrder = allowedOrders.contains(order.toUpperCase()) ? order : "ASC";
String sql = "SELECT * FROM products WHERE category = ? ORDER BY " + sort + " " + safeOrder;
List<Map<String, Object>> products = jdbc.queryForList(sql, category);
```

### Complexity Rationale
This is rated Moderate because the method contains a mix of safe patterns (column allowlist validation) and unsafe patterns (category concatenation, unvalidated order direction). A reviewer must distinguish between the validated and unvalidated parameters.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because while the category concatenation is detectable, the partial validation of the sort column may cause some tools to reduce the severity or skip the finding. Tools need to analyze each parameter independently.

---

## Vulnerability: StringBuilder Concatenation in Order Listing Filters

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Moderate  
**Detection Difficulty:** Pattern_Dependent  
**Affected Lines:** L100-L108  

### Description
The `listOrders` method uses a `StringBuilder` to construct a SQL query. While the `customerId` parameter is properly parameterized with a `?` placeholder, the `status`, `dateFrom`, and `dateTo` parameters are appended directly into the SQL string using `StringBuilder.append()`. This creates injection points in the filter conditions despite the base query being parameterized.

### Exploitation Scenario
An attacker sends `GET /api/orders?customerId=1&status=' OR '1'='1' UNION SELECT 1,2,3,4,username,email FROM customers--`. The status value is appended directly into the SQL, breaking out of the intended filter and allowing arbitrary query manipulation. The `dateFrom` and `dateTo` parameters offer additional injection vectors: `GET /api/orders?customerId=1&dateFrom=' OR '1'='1`.

### Remediation Guidance
Use parameterized placeholders for all filter values:
```java
if (status != null && !status.isEmpty()) {
    sql.append(" AND o.status = ?");
    params.add(status);
}
if (dateFrom != null && !dateFrom.isEmpty()) {
    sql.append(" AND o.created_at >= ?");
    params.add(dateFrom);
}
```

### Complexity Rationale
This is rated Moderate because the method mixes parameterized and non-parameterized query construction. The `customerId` is safely parameterized, which may lead a reviewer to assume all parameters are handled similarly. The vulnerability requires examining each `append()` call individually.

### Detection Difficulty Rationale
This is rated Pattern_Dependent because SAST tools must track the StringBuilder's content through multiple conditional append operations and distinguish between the parameterized base query and the concatenated filter values. Tools with StringBuilder-aware taint tracking will detect this, but simpler pattern matchers may not.

---

## Vulnerability: Direct Concatenation in DELETE Statement

**CWE:** CWE-89  
**OWASP:** A03  
**Complexity Level:** Obvious  
**Detection Difficulty:** Easily_Detectable  
**Affected Lines:** L161-L162  

### Description
The `deleteProductsByCategory` method constructs a `DELETE` SQL statement by directly concatenating the `category` request parameter into the query string. This allows an attacker to manipulate the DELETE operation to affect arbitrary rows or execute additional SQL statements.

### Exploitation Scenario
An attacker sends `DELETE /api/products?category=' OR '1'='1`. The injected payload modifies the WHERE clause to match all rows, causing the deletion of every product in the database. A more targeted attack could use `category=' OR name='CompetitorProduct` to selectively delete specific products.

### Remediation Guidance
Use a parameterized query:
```java
String sql = "DELETE FROM products WHERE category = ?";
int deleted = jdbc.update(sql, category);
```

### Complexity Rationale
This is rated Obvious because the user input flows directly from the `@RequestParam` into string concatenation within a destructive SQL statement, with no intermediate processing or validation.

### Detection Difficulty Rationale
This is rated Easily_Detectable because direct string concatenation in a SQL statement is a standard pattern that all SAST tools detect reliably. The use of a DELETE statement makes this particularly notable.
