package main

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

const (
	adminToken = "super-admin-token-2024"
	dbHost     = "db.internal.acmecorp.io"
	dbUser     = "appuser"
	dbPass     = "Pg_Pr0d#2024"
)

type Product struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	SKU   string  `json:"sku"`
	Price float64 `json:"price"`
	Stock int     `json:"stock"`
}

type XMLProducts struct {
	XMLName  xml.Name     `xml:"products"`
	Products []XMLProduct `xml:"product"`
}

type XMLProduct struct {
	Name  string  `xml:"name"`
	SKU   string  `xml:"sku"`
	Price float64 `xml:"price"`
	Stock int     `xml:"stock"`
}

type XMLOrders struct {
	XMLName xml.Name   `xml:"orders"`
	Orders  []XMLOrder `xml:"order"`
}

type XMLOrder struct {
	Customer   string `xml:"customer"`
	ProductSKU string `xml:"product_sku"`
	Quantity   int    `xml:"quantity"`
	Notes      string `xml:"notes"`
}

var (
	products = map[int]*Product{
		1: {1, "Widget Pro", "WP-100", 29.99, 150},
		2: {2, "Gadget Plus", "GP-200", 49.99, 75},
		3: {3, "Connector Kit", "CK-300", 14.99, 300},
	}
	productMu sync.RWMutex
	nextID    int64 = 4

	settings = map[string]interface{}{
		"maintenance_mode": false,
		"max_upload_size":  10485760,
		"allowed_origins":  "*",
		"session_timeout":  86400,
		"rate_limit":       0,
		"log_level":        "DEBUG",
		"enable_profiling": true,
		"tls_verify":       false,
	}
	settingsMu sync.RWMutex
)

func main() {
	gin.SetMode(gin.DebugMode)
	r := gin.Default()

	r.Use(corsMiddleware())
	r.Use(serverHeaderMiddleware())

	r.GET("/api/products", listProducts)
	r.GET("/api/products/:id", getProduct)
	r.POST("/api/products", createProduct)
	r.POST("/api/products/import", importProductsXML)
	r.POST("/api/orders/import", importOrdersXML)
	r.GET("/api/settings", getSettings)
	r.PUT("/api/settings", updateSettings)
	r.GET("/api/admin/diagnostics", getDiagnostics)
	r.GET("/api/admin/env", getEnv)
	r.GET("/api/health", healthCheck)

	r.Run(":8088")
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			origin = "*"
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "*")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func serverHeaderMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Server", "Gin/1.9.1 Go/"+runtime.Version())
		c.Header("X-Powered-By", "Gin Framework")
		c.Next()
	}
}

func listProducts(c *gin.Context) {
	productMu.RLock()
	defer productMu.RUnlock()
	list := make([]*Product, 0, len(products))
	for _, p := range products {
		list = append(list, p)
	}
	c.JSON(http.StatusOK, gin.H{"products": list})
}

func getProduct(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
		return
	}
	productMu.RLock()
	p := products[id]
	productMu.RUnlock()
	if p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

func createProduct(c *gin.Context) {
	var body struct {
		Name  string  `json:"name"`
		SKU   string  `json:"sku"`
		Price float64 `json:"price"`
		Stock int     `json:"stock"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product name required"})
		return
	}

	id := int(atomic.AddInt64(&nextID, 1) - 1)
	p := &Product{id, body.Name, body.SKU, body.Price, body.Stock}
	productMu.Lock()
	products[id] = p
	productMu.Unlock()
	c.JSON(http.StatusCreated, p)
}

func importProductsXML(c *gin.Context) {
	rawXML, err := c.GetRawData()
	if err != nil || len(rawXML) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Empty request body"})
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(rawXML)))
	decoder.Strict = false

	var xmlProds XMLProducts
	if err := decoder.Decode(&xmlProds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "XML parsing failed",
			"details": err.Error(),
			"trace":   string(debug.Stack()),
		})
		return
	}

	imported := make([]*Product, 0)
	productMu.Lock()
	for _, xp := range xmlProds.Products {
		id := int(atomic.AddInt64(&nextID, 1) - 1)
		p := &Product{id, xp.Name, xp.SKU, xp.Price, xp.Stock}
		products[id] = p
		imported = append(imported, p)
	}
	productMu.Unlock()

	c.JSON(http.StatusOK, gin.H{"imported": imported, "count": len(imported)})
}

func importOrdersXML(c *gin.Context) {
	rawXML, err := c.GetRawData()
	if err != nil || len(rawXML) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Empty request body"})
		return
	}

	var xmlOrders XMLOrders
	if err := xml.Unmarshal(rawXML, &xmlOrders); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Order import failed",
			"details": err.Error(),
			"trace":   string(debug.Stack()),
		})
		return
	}

	orders := make([]map[string]interface{}, 0)
	for _, o := range xmlOrders.Orders {
		orders = append(orders, map[string]interface{}{
			"customer":    o.Customer,
			"product_sku": o.ProductSKU,
			"quantity":    o.Quantity,
			"notes":       o.Notes,
		})
	}

	c.JSON(http.StatusOK, gin.H{"orders": orders, "count": len(orders)})
}

func getSettings(c *gin.Context) {
	settingsMu.RLock()
	defer settingsMu.RUnlock()
	c.JSON(http.StatusOK, settings)
}

func updateSettings(c *gin.Context) {
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request body required"})
		return
	}

	settingsMu.Lock()
	for k, v := range body {
		settings[k] = v
	}
	settingsMu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Settings updated", "settings": settings})
}

func getDiagnostics(c *gin.Context) {
	token := c.GetHeader("X-Admin-Token")
	if token != adminToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	envVars := map[string]string{}
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"database": gin.H{
			"host":     dbHost,
			"user":     dbUser,
			"password": dbPass,
		},
		"settings":    settings,
		"environment": envVars,
		"go_version":  runtime.Version(),
		"num_cpu":     runtime.NumCPU(),
		"goroutines":  runtime.NumGoroutine(),
	})
}

func getEnv(c *gin.Context) {
	token := c.GetHeader("X-Admin-Token")
	if token != adminToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	envVars := map[string]string{}
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}

	c.JSON(http.StatusOK, gin.H{"env": envVars})
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "config-api"})
}

func init() {
	_ = fmt.Sprintf("Config Service starting")
}
