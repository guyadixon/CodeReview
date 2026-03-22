package main

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	SSN        string `json:"ssn"`
	Salary     int    `json:"salary"`
	Department string `json:"department"`
}

type Ticket struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	AssigneeID  int    `json:"assignee_id"`
	Priority    string `json:"priority"`
	Status      string `json:"status"`
	Internal    string `json:"internal_notes"`
}

type Session struct {
	UserID int
	Role   string
}

var (
	mu       sync.RWMutex
	users    map[int]*User
	tickets  map[int]*Ticket
	sessions map[string]*Session
)

func init() {
	users = map[int]*User{
		1: {ID: 1, Username: "alice", Email: "alice@helpdesk.io", Role: "admin",
			SSN: "123-45-6789", Salary: 140000, Department: "engineering"},
		2: {ID: 2, Username: "bob", Email: "bob@helpdesk.io", Role: "agent",
			SSN: "987-65-4321", Salary: 90000, Department: "support"},
		3: {ID: 3, Username: "charlie", Email: "charlie@helpdesk.io", Role: "customer",
			SSN: "555-12-3456", Salary: 0, Department: ""},
		4: {ID: 4, Username: "diana", Email: "diana@helpdesk.io", Role: "customer",
			SSN: "444-33-2211", Salary: 0, Department: ""},
	}

	tickets = map[int]*Ticket{
		301: {ID: 301, Title: "Login page broken", Description: "Cannot log in since last update",
			AssigneeID: 2, Priority: "high", Status: "open",
			Internal: "Likely caused by auth service deploy at 2am"},
		302: {ID: 302, Title: "Billing discrepancy", Description: "Charged twice for subscription",
			AssigneeID: 2, Priority: "medium", Status: "in_progress",
			Internal: "Stripe webhook fired twice, refund pending"},
		303: {ID: 303, Title: "Feature request: dark mode", Description: "Please add dark mode",
			AssigneeID: 0, Priority: "low", Status: "open",
			Internal: "Low priority, backlog for Q2"},
	}

	sessions = map[string]*Session{
		"tok_alice":   {UserID: 1, Role: "admin"},
		"tok_bob":     {UserID: 2, Role: "agent"},
		"tok_charlie": {UserID: 3, Role: "customer"},
		"tok_diana":   {UserID: 4, Role: "customer"},
	}
}

func getSession(c *gin.Context) *Session {
	auth := c.GetHeader("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	return sessions[token]
}

func main() {
	r := gin.Default()

	r.GET("/api/users/:id", getUserProfile)
	r.GET("/api/tickets/:id", getTicket)
	r.PUT("/api/tickets/:id", updateTicket)
	r.GET("/api/admin/users", listAllUsers)
	r.PUT("/api/users/:id/role", updateUserRole)
	r.GET("/api/debug/config", debugConfig)
	r.DELETE("/api/tickets/:id", deleteTicket)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}
	r.Run(":" + port)
}

func getUserProfile(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	mu.RLock()
	user := users[id]
	mu.RUnlock()

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func getTicket(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ticket ID"})
		return
	}

	mu.RLock()
	ticket := tickets[id]
	mu.RUnlock()

	if ticket == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
		return
	}

	c.JSON(http.StatusOK, ticket)
}

func updateTicket(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ticket ID"})
		return
	}

	mu.Lock()
	ticket := tickets[id]
	mu.Unlock()

	if ticket == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
		return
	}

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if v, ok := body["title"].(string); ok {
		ticket.Title = v
	}
	if v, ok := body["description"].(string); ok {
		ticket.Description = v
	}
	if v, ok := body["priority"].(string); ok {
		ticket.Priority = v
	}
	if v, ok := body["status"].(string); ok {
		ticket.Status = v
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ticket updated", "ticket": ticket})
}

func deleteTicket(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	if sess.Role != "admin" && sess.Role != "agent" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ticket ID"})
		return
	}

	mu.Lock()
	delete(tickets, id)
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Ticket deleted"})
}

func listAllUsers(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	clientRole := c.GetHeader("X-User-Role")
	if clientRole != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	mu.RLock()
	userList := make([]*User, 0, len(users))
	for _, u := range users {
		userList = append(userList, u)
	}
	mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{"users": userList})
}

func updateUserRole(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	mu.Lock()
	user := users[id]
	mu.Unlock()

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var body map[string]string
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	newRole := body["role"]
	if newRole == "" {
		newRole = "customer"
	}
	user.Role = newRole

	c.JSON(http.StatusOK, gin.H{"message": "Role updated", "userId": id, "newRole": newRole})
}

func debugConfig(c *gin.Context) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://admin:s3cret@db:5432/ticketdb"
	}
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		secret = "helpdesk-session-secret-key"
	}

	c.JSON(http.StatusOK, gin.H{
		"databaseUrl":   dbURL,
		"sessionSecret": secret,
		"apiKeys": gin.H{
			"twilio":  getEnvDefault("TWILIO_KEY", "AC_twilio_key_123"),
			"mailgun": getEnvDefault("MAILGUN_KEY", "mg_key_456"),
		},
		"goVersion":    "1.21",
		"sessionCount": len(sessions),
	})
}

func getEnvDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
