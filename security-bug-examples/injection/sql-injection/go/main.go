package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./inventory.db")
	if err != nil {
		log.Fatal(err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		category TEXT NOT NULL,
		price REAL NOT NULL,
		stock INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS customers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		email TEXT NOT NULL,
		membership_tier TEXT DEFAULT 'basic'
	);
	CREATE TABLE IF NOT EXISTS orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		customer_id INTEGER NOT NULL,
		product_id INTEGER NOT NULL,
		quantity INTEGER NOT NULL,
		status TEXT DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(schema)
	if err != nil {
		log.Fatal(err)
	}
}

func searchProducts(c *gin.Context) {
	keyword := c.Query("q")
	query := "SELECT id, name, category, price, stock FROM products WHERE name LIKE '%" + keyword + "%'"
	rows, err := db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var products []gin.H
	for rows.Next() {
		var id, stock int
		var name, category string
		var price float64
		rows.Scan(&id, &name, &category, &price, &stock)
		products = append(products, gin.H{
			"id": id, "name": name, "category": category,
			"price": price, "stock": stock,
		})
	}
	c.JSON(http.StatusOK, products)
}

func buildProductQuery(category, sortCol, sortDir string) string {
	allowedCols := map[string]bool{"name": true, "price": true, "stock": true, "category": true}
	if !allowedCols[sortCol] {
		sortCol = "name"
	}

	base := "SELECT id, name, category, price, stock FROM products"
	if category != "" {
		base += " WHERE category = '" + category + "'"
	}
	base += fmt.Sprintf(" ORDER BY %s %s", sortCol, sortDir)
	return base
}

func listProducts(c *gin.Context) {
	category := c.Query("category")
	sortCol := c.DefaultQuery("sort", "name")
	sortDir := c.DefaultQuery("order", "ASC")

	query := buildProductQuery(category, sortCol, sortDir)
	rows, err := db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var products []gin.H
	for rows.Next() {
		var id, stock int
		var name, cat string
		var price float64
		rows.Scan(&id, &name, &cat, &price, &stock)
		products = append(products, gin.H{
			"id": id, "name": name, "category": cat,
			"price": price, "stock": stock,
		})
	}
	c.JSON(http.StatusOK, products)
}

func listOrders(c *gin.Context) {
	customerID := c.Query("customer_id")
	if customerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "customer_id is required"})
		return
	}

	query := "SELECT o.id, o.customer_id, o.product_id, o.quantity, o.status, " +
		"p.name as product_name FROM orders o " +
		"JOIN products p ON o.product_id = p.id " +
		"WHERE o.customer_id = ?"

	args := []interface{}{customerID}

	if status := c.Query("status"); status != "" {
		query += " AND o.status = '" + status + "'"
	}

	if tags := c.Query("tags"); tags != "" {
		tagList := strings.Split(tags, ",")
		for _, tag := range tagList {
			query += fmt.Sprintf(" AND p.name LIKE '%%%s%%'", strings.TrimSpace(tag))
		}
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var orders []gin.H
	for rows.Next() {
		var id, custID, prodID, qty int
		var status, productName string
		rows.Scan(&id, &custID, &prodID, &qty, &status, &productName)
		orders = append(orders, gin.H{
			"id": id, "customer_id": custID, "product_id": prodID,
			"quantity": qty, "status": status, "product_name": productName,
		})
	}
	c.JSON(http.StatusOK, orders)
}

func getCustomer(c *gin.Context) {
	id := c.Param("id")
	row := db.QueryRow("SELECT id, username, email, membership_tier FROM customers WHERE id = ?", id)

	var custID int
	var username, email, tier string
	if err := row.Scan(&custID, &username, &email, &tier); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": custID, "username": username, "email": email, "membership_tier": tier,
	})
}

type CreateProductRequest struct {
	Name     string  `json:"name" binding:"required"`
	Category string  `json:"category" binding:"required"`
	Price    float64 `json:"price" binding:"required"`
	Stock    int     `json:"stock"`
}

func createProduct(c *gin.Context) {
	var req CreateProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := db.Exec(
		"INSERT INTO products (name, category, price, stock) VALUES (?, ?, ?, ?)",
		req.Name, req.Category, req.Price, req.Stock,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "Product created"})
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	r.GET("/api/products/search", searchProducts)
	r.GET("/api/products", listProducts)
	r.GET("/api/orders", listOrders)
	r.GET("/api/customers/:id", getCustomer)
	r.POST("/api/products", createProduct)

	r.Run(":8080")
}
