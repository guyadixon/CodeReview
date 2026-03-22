package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Role       string `json:"role"`
	Active     bool   `json:"active"`
	MFAEnabled bool   `json:"mfa_enabled"`
	APIKey     string `json:"api_key"`
}

type SessionInfo struct {
	UserID  int
	Created time.Time
}

type Transaction struct {
	ID          int     `json:"id"`
	UserID      int     `json:"user_id"`
	Amount      float64 `json:"amount"`
	Recipient   string  `json:"recipient"`
	Description string  `json:"description"`
	Timestamp   int64   `json:"timestamp"`
	Status      string  `json:"status"`
}

var (
	users        = map[int]*User{}
	sessions     = map[string]*SessionInfo{}
	transactions []*Transaction
	mu           sync.RWMutex
	apiSecret    = "sk-prod-logging-8a7b6c5d4e3f"
)

func init() {
	users[1] = &User{1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", true, true, "ak-admin-x7k9m2"}
	users[2] = &User{2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", true, false, "ak-jdoe-p3q8r1"}
	users[3] = &User{3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", true, false, "ak-asmith-w5t6y4"}
	users[4] = &User{4, "bwilson", "bwilson@acmecorp.io", "B0b_W1ls0n", "analyst", false, false, "ak-bwilson-z2v8n3"}
}

func generateToken(userID int) string {
	raw := fmt.Sprintf("%d-%d", userID, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(raw))
	token := fmt.Sprintf("%x", hash[:16])
	mu.Lock()
	sessions[token] = &SessionInfo{UserID: userID, Created: time.Now()}
	mu.Unlock()
	return token
}

func getSession(c *gin.Context) *SessionInfo {
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		mu.RLock()
		s := sessions[auth[7:]]
		mu.RUnlock()
		return s
	}
	return nil
}

func main() {
	r := gin.Default()

	r.POST("/api/login", handleLogin)
	r.GET("/api/admin/users", handleListUsers)
	r.PUT("/api/admin/users/:id/role", handleChangeRole)
	r.POST("/api/admin/users/:id/deactivate", handleDeactivateUser)
	r.POST("/api/transactions", handleCreateTransaction)
	r.POST("/api/transactions/bulk", handleBulkTransfer)
	r.POST("/api/export/data", handleExportData)
	r.POST("/api/settings/api-key", handleRegenerateAPIKey)
	r.PUT("/api/settings/mfa", handleToggleMFA)
	r.POST("/api/validate-key", handleValidateKey)
	r.GET("/api/health", handleHealthCheck)

	r.Run(":8089")
}

func handleLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request body required"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	for uid, user := range users {
		if user.Username == body.Username {
			if !user.Active {
				c.JSON(http.StatusForbidden, gin.H{"error": "Account disabled"})
				return
			}

			if user.Password == body.Password {
				token := generateToken(uid)
				c.JSON(http.StatusOK, gin.H{
					"token":    token,
					"user_id":  uid,
					"role":     user.Role,
					"password": user.Password,
					"api_key":  user.APIKey,
				})
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
	}

	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
}

func handleListUsers(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	var result []gin.H
	for _, u := range users {
		result = append(result, gin.H{
			"id": u.ID, "username": u.Username, "email": u.Email,
			"role": u.Role, "active": u.Active,
		})
	}
	c.JSON(http.StatusOK, gin.H{"users": result})
}

func handleChangeRole(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	targetID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Role required"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	target := users[targetID]
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Target user not found"})
		return
	}

	oldRole := target.Role
	target.Role = body.Role

	c.JSON(http.StatusOK, gin.H{
		"message":  "Role updated",
		"user_id":  targetID,
		"old_role": oldRole,
		"new_role": body.Role,
	})
}

func handleDeactivateUser(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	caller := users[session.UserID]
	if caller == nil || caller.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	targetID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	target := users[targetID]
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Target user not found"})
		return
	}

	target.Active = false
	c.JSON(http.StatusOK, gin.H{"message": "User deactivated", "user_id": targetID})
}

func handleCreateTransaction(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Amount      float64 `json:"amount"`
		Recipient   string  `json:"recipient"`
		Description string  `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Recipient == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Recipient required"})
		return
	}

	mu.Lock()
	tx := &Transaction{
		ID:          len(transactions) + 1,
		UserID:      session.UserID,
		Amount:      body.Amount,
		Recipient:   body.Recipient,
		Description: body.Description,
		Timestamp:   time.Now().Unix(),
		Status:      "completed",
	}
	transactions = append(transactions, tx)
	mu.Unlock()

	c.JSON(http.StatusCreated, gin.H{"message": "Transaction completed", "transaction": tx})
}

func handleBulkTransfer(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Transfers []struct {
			Amount      float64 `json:"amount"`
			Recipient   string  `json:"recipient"`
			Description string  `json:"description"`
		} `json:"transfers"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Transfers array required"})
		return
	}

	mu.Lock()
	var results []*Transaction
	for _, t := range body.Transfers {
		tx := &Transaction{
			ID:          len(transactions) + 1,
			UserID:      session.UserID,
			Amount:      t.Amount,
			Recipient:   t.Recipient,
			Description: t.Description,
			Timestamp:   time.Now().Unix(),
			Status:      "completed",
		}
		transactions = append(transactions, tx)
		results = append(results, tx)
	}
	mu.Unlock()

	c.JSON(http.StatusCreated, gin.H{
		"message":      fmt.Sprintf("%d transfers completed", len(results)),
		"transactions": results,
	})
}

func handleExportData(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Type string `json:"type"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Export type required"})
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	if body.Type == "users" {
		var exportData []gin.H
		for _, u := range users {
			exportData = append(exportData, gin.H{
				"id": u.ID, "username": u.Username, "email": u.Email,
				"password": u.Password, "api_key": u.APIKey, "role": u.Role,
			})
		}
		c.JSON(http.StatusOK, gin.H{"export": exportData})
		return
	}

	if body.Type == "transactions" {
		c.JSON(http.StatusOK, gin.H{"export": transactions})
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown export type"})
}

func handleRegenerateAPIKey(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	user := users[session.UserID]
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	oldKey := user.APIKey
	raw := fmt.Sprintf("%s%d", user.Username, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(raw))
	newKey := fmt.Sprintf("ak-%x", hash[:6])
	user.APIKey = newKey

	c.JSON(http.StatusOK, gin.H{
		"message": "API key regenerated",
		"old_key": oldKey,
		"new_key": newKey,
	})
}

func handleToggleMFA(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request body required"})
		return
	}

	mu.Lock()
	user := users[session.UserID]
	if user == nil {
		mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	user.MFAEnabled = body.Enabled
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "MFA setting updated", "mfa_enabled": body.Enabled})
}

func handleValidateKey(c *gin.Context) {
	var body struct {
		APIKey string `json:"api_key"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API key required"})
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	for _, user := range users {
		if user.APIKey == body.APIKey {
			c.JSON(http.StatusOK, gin.H{
				"valid":    true,
				"user_id":  user.ID,
				"username": user.Username,
				"role":     user.Role,
			})
			return
		}
	}

	c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
}

func handleHealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "logging-api"})
}
