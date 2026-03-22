package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

type Product struct {
	ID       int     `json:"id" yaml:"id"`
	Name     string  `json:"name" yaml:"name"`
	Price    float64 `json:"price" yaml:"price"`
	Stock    int     `json:"stock" yaml:"stock"`
	Category string  `json:"category" yaml:"category"`
}

type OrderItem struct {
	ProductID int     `json:"product_id"`
	Name      string  `json:"name"`
	Quantity  int     `json:"quantity"`
	Subtotal  float64 `json:"subtotal"`
}

type Order struct {
	ID            int         `json:"id"`
	Items         []OrderItem `json:"items"`
	Total         float64     `json:"total"`
	Status        string      `json:"status"`
	CustomerEmail string      `json:"customer_email"`
}

var (
	products     = map[int]*Product{}
	orders       = map[int]*Order{}
	mu           sync.RWMutex
	orderCounter int64 = 1000
)

var warehouseConfig = map[string]interface{}{
	"location":       "us-east-1",
	"api_endpoint":   "https://warehouse.internal.acmecorp.io/api/v2",
	"max_batch_size": 50,
	"retry_attempts": 3,
}

func init() {
	products[1] = &Product{1, "Widget Pro", 29.99, 150, "hardware"}
	products[2] = &Product{2, "Gadget Plus", 49.99, 75, "electronics"}
	products[3] = &Product{3, "Tool Kit Standard", 19.99, 200, "tools"}
	products[4] = &Product{4, "Sensor Array", 89.99, 30, "electronics"}
	products[5] = &Product{5, "Cable Bundle", 9.99, 500, "accessories"}
}

func main() {
	r := gin.Default()

	r.GET("/api/products", listProducts)
	r.GET("/api/products/:id", getProduct)
	r.POST("/api/orders", createOrder)
	r.GET("/api/orders/:id", getOrder)
	r.POST("/api/inventory/import", importInventory)
	r.GET("/api/products/:id/label", generateLabel)
	r.POST("/api/warehouse/sync", syncWarehouse)
	r.GET("/api/config/warehouse", getWarehouseConfig)
	r.GET("/api/health", healthCheck)

	r.Run(":8010")
}

func listProducts(c *gin.Context) {
	category := c.Query("category")
	mu.RLock()
	defer mu.RUnlock()

	result := []Product{}
	for _, p := range products {
		if category == "" || p.Category == category {
			result = append(result, *p)
		}
	}
	c.JSON(http.StatusOK, gin.H{"products": result, "total": len(result)})
}

func getProduct(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
		return
	}

	mu.RLock()
	p := products[id]
	mu.RUnlock()

	if p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

func createOrder(c *gin.Context) {
	var body struct {
		Items []struct {
			ProductID int `json:"product_id"`
			Quantity  int `json:"quantity"`
		} `json:"items"`
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one item required"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	var orderItems []OrderItem
	var total float64

	for _, item := range body.Items {
		p := products[item.ProductID]
		if p == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Product %d not found", item.ProductID)})
			return
		}
		qty := item.Quantity
		if qty <= 0 {
			qty = 1
		}
		if p.Stock < qty {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Insufficient stock for %s", p.Name)})
			return
		}
		p.Stock -= qty
		subtotal := p.Price * float64(qty)
		total += subtotal
		orderItems = append(orderItems, OrderItem{
			ProductID: p.ID, Name: p.Name, Quantity: qty,
			Subtotal: math.Round(subtotal*100) / 100,
		})
	}

	orderID := int(atomic.AddInt64(&orderCounter, 1))
	orders[orderID] = &Order{
		ID: orderID, Items: orderItems,
		Total: math.Round(total*100) / 100, Status: "confirmed",
		CustomerEmail: body.Email,
	}

	c.JSON(http.StatusCreated, gin.H{
		"order_id": orderID, "total": math.Round(total*100) / 100, "status": "confirmed",
	})
}

func getOrder(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid order ID"})
		return
	}

	mu.RLock()
	order := orders[id]
	mu.RUnlock()

	if order == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Order not found"})
		return
	}
	c.JSON(http.StatusOK, order)
}

func importInventory(c *gin.Context) {
	var body struct {
		Format  string          `json:"format"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Payload required"})
		return
	}

	type inventoryData struct {
		Products []struct {
			ID    int     `json:"id" yaml:"id"`
			Stock int     `json:"stock" yaml:"stock"`
			Price float64 `json:"price" yaml:"price"`
		} `json:"products" yaml:"products"`
	}

	var data inventoryData
	var parseErr error

	if body.Format == "yaml" {
		var raw string
		json.Unmarshal(body.Payload, &raw)
		parseErr = yaml.Unmarshal([]byte(raw), &data)
	} else {
		parseErr = json.Unmarshal(body.Payload, &data)
	}

	if parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parse failed", "details": parseErr.Error()})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	updated := 0
	for _, entry := range data.Products {
		if p, ok := products[entry.ID]; ok {
			if entry.Stock > 0 {
				p.Stock = entry.Stock
			}
			if entry.Price > 0 {
				p.Price = entry.Price
			}
			updated++
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Inventory updated", "updated_count": updated})
}

func generateLabel(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
		return
	}

	mu.RLock()
	p := products[id]
	mu.RUnlock()

	if p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	label := fmt.Sprintf("%s - $%.2f [%s]", p.Name, p.Price, p.Category)
	c.JSON(http.StatusOK, gin.H{"label": label, "product_id": id})
}

func syncWarehouse(c *gin.Context) {
	var body struct {
		Endpoint string `json:"endpoint"`
	}
	c.ShouldBindJSON(&body)

	target := warehouseConfig["api_endpoint"].(string)
	if body.Endpoint != "" {
		target = body.Endpoint
	}

	mu.RLock()
	inventory := make([]map[string]interface{}, 0)
	for _, p := range products {
		inventory = append(inventory, map[string]interface{}{
			"id": p.ID, "name": p.Name, "stock": p.Stock,
		})
	}
	mu.RUnlock()

	client := &http.Client{}
	payload, _ := json.Marshal(map[string]interface{}{"inventory": inventory})
	req, _ := http.NewRequest("POST", target, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Body = http.NoBody

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Sync failed", "details": err.Error()})
		return
	}
	defer resp.Body.Close()

	_ = payload
	c.JSON(http.StatusOK, gin.H{"status": "synced", "remote_status": resp.StatusCode})
}

func getWarehouseConfig(c *gin.Context) {
	c.JSON(http.StatusOK, warehouseConfig)
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "inventory-api"})
}
