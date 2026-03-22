package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Role     string `json:"role"`
	Active   bool   `json:"active"`
	APIKey   string `json:"api_key"`
}

type SessionInfo struct {
	UserID  int   `json:"user_id"`
	Created int64 `json:"created"`
}

type WebhookEntry struct {
	ID          string `json:"id"`
	CallbackURL string `json:"callback_url"`
	EventType   string `json:"event_type"`
	UserID      int    `json:"user_id"`
	Created     int64  `json:"created"`
}

var (
	users    map[int]*User
	sessions map[string]*SessionInfo
	webhooks map[string]*WebhookEntry
	mu       sync.RWMutex
)

func init() {
	users = map[int]*User{
		1: {ID: 1, Username: "admin", Email: "admin@acmecorp.io", Password: "Adm1n_Pr0d!", Role: "admin", Active: true, APIKey: "ak-admin-x7k9m2"},
		2: {ID: 2, Username: "jdoe", Email: "jdoe@acmecorp.io", Password: "JohnD_2024", Role: "manager", Active: true, APIKey: "ak-jdoe-p3q8r1"},
		3: {ID: 3, Username: "asmith", Email: "asmith@acmecorp.io", Password: "alice_pass", Role: "developer", Active: true, APIKey: "ak-asmith-w5t6y4"},
	}
	sessions = make(map[string]*SessionInfo)
	webhooks = make(map[string]*WebhookEntry)
}

func generateToken(userID int) string {
	raw := fmt.Sprintf("%d-%d", userID, time.Now().UnixNano())
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)[:32]
}

func getSession(c *gin.Context) *SessionInfo {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		mu.RLock()
		defer mu.RUnlock()
		return sessions[auth[7:]]
	}
	return nil
}

func doHTTPGet(targetURL string) (int, string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

func main() {
	r := gin.Default()

	r.POST("/api/login", handleLogin)
	r.POST("/api/fetch-url", handleFetchURL)
	r.GET("/api/preview", handlePreview)
	r.POST("/api/webhooks", handleRegisterWebhook)
	r.POST("/api/webhooks/:id/test", handleTestWebhook)
	r.POST("/api/integrations/import", handleImportConfig)
	r.GET("/api/proxy", handleProxy)
	r.GET("/api/health", handleHealthCheck)

	r.Run(":8010")
}

func handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	for id, user := range users {
		if user.Username == req.Username && user.Password == req.Password {
			if !user.Active {
				c.JSON(403, gin.H{"error": "Account disabled"})
				return
			}
			token := generateToken(id)
			mu.Lock()
			sessions[token] = &SessionInfo{UserID: id, Created: time.Now().Unix()}
			mu.Unlock()
			c.JSON(200, gin.H{"token": token, "user_id": id, "role": user.Role})
			return
		}
	}
	c.JSON(401, gin.H{"error": "Invalid credentials"})
}

func handleFetchURL(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.URL == "" {
		c.JSON(400, gin.H{"error": "URL parameter required"})
		return
	}

	status, body, err := doHTTPGet(req.URL)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}

	preview := body
	if len(preview) > 5000 {
		preview = preview[:5000]
	}
	c.JSON(200, gin.H{"status": status, "content_length": len(body), "body": preview})
}

func handlePreview(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	target := c.Query("target")
	if target == "" {
		c.JSON(400, gin.H{"error": "target parameter required"})
		return
	}

	parsed, err := url.Parse(target)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid URL"})
		return
	}

	blockedHosts := []string{"localhost", "127.0.0.1"}
	for _, h := range blockedHosts {
		if parsed.Hostname() == h {
			c.JSON(403, gin.H{"error": "Blocked host"})
			return
		}
	}

	_, body, err := doHTTPGet(target)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}

	preview := body
	if len(preview) > 2000 {
		preview = preview[:2000]
	}
	c.JSON(200, gin.H{"url": target, "preview": preview})
}

func handleRegisterWebhook(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	var req struct {
		CallbackURL string `json:"callback_url"`
		EventType   string `json:"event_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.CallbackURL == "" {
		c.JSON(400, gin.H{"error": "callback_url required"})
		return
	}

	parsed, err := url.Parse(req.CallbackURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		c.JSON(400, gin.H{"error": "Only HTTP(S) callbacks supported"})
		return
	}

	if req.EventType == "" {
		req.EventType = "default"
	}

	raw := fmt.Sprintf("%s%d", req.CallbackURL, time.Now().UnixNano())
	h := md5.Sum([]byte(raw))
	webhookID := fmt.Sprintf("%x", h)[:12]

	mu.Lock()
	webhooks[webhookID] = &WebhookEntry{
		ID:          webhookID,
		CallbackURL: req.CallbackURL,
		EventType:   req.EventType,
		UserID:      session.UserID,
		Created:     time.Now().Unix(),
	}
	mu.Unlock()

	c.JSON(201, gin.H{"message": "Webhook registered", "webhook_id": webhookID})
}

func handleTestWebhook(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	webhookID := c.Param("id")
	mu.RLock()
	webhook, exists := webhooks[webhookID]
	mu.RUnlock()

	if !exists {
		c.JSON(404, gin.H{"error": "Webhook not found"})
		return
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"event":     "test",
		"timestamp": time.Now().Unix(),
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhook.CallbackURL, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		c.JSON(502, gin.H{"error": fmt.Sprintf("Delivery failed: %s", err.Error())})
		return
	}
	defer resp.Body.Close()

	c.JSON(200, gin.H{"message": "Webhook delivered", "status": resp.StatusCode})
}

func handleImportConfig(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	var req struct {
		ConfigURL string `json:"config_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ConfigURL == "" {
		c.JSON(400, gin.H{"error": "config_url required"})
		return
	}

	parsed, err := url.Parse(req.ConfigURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		c.JSON(400, gin.H{"error": "Only HTTP(S) URLs supported"})
		return
	}

	if parsed.Hostname() != "" && strings.HasPrefix(parsed.Hostname(), "169.254") {
		c.JSON(403, gin.H{"error": "Metadata endpoints not allowed"})
		return
	}

	_, body, err := doHTTPGet(req.ConfigURL)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}

	var config interface{}
	if jsonErr := json.Unmarshal([]byte(body), &config); jsonErr != nil {
		c.JSON(400, gin.H{"error": "Invalid JSON at URL"})
		return
	}

	c.JSON(200, gin.H{"message": "Configuration imported", "config": config})
}

func handleProxy(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	service := c.Query("service")
	path := c.DefaultQuery("path", "/")
	baseURL := c.Query("base_url")

	serviceMap := map[string]string{
		"analytics":     "http://analytics-service:8081",
		"billing":       "http://billing-service:8082",
		"notifications": "http://notifications-service:8083",
	}

	resolvedBase, ok := serviceMap[service]
	if !ok {
		resolvedBase = baseURL
		if resolvedBase == "" {
			c.JSON(400, gin.H{"error": "Unknown service"})
			return
		}
	}

	fullURL := resolvedBase + path

	status, body, err := doHTTPGet(fullURL)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}

	preview := body
	if len(preview) > 5000 {
		preview = preview[:5000]
	}
	c.JSON(200, gin.H{"status": status, "body": preview})
}

func handleHealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{"status": "healthy", "service": "gateway-api"})
}
