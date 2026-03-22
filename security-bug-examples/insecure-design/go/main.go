package main

import (
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID             int    `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	Role           string `json:"role"`
	Active         bool   `json:"active"`
	FailedAttempts int    `json:"failed_attempts"`
}

type SessionInfo struct {
	UserID  int
	Created time.Time
}

var (
	users             = map[int]*User{}
	sessions          = map[string]*SessionInfo{}
	passwordResetTkns = map[string]int{}
	mu                sync.RWMutex
	dbDSN             = "host=db.internal.acmecorp.io port=5432 user=appuser password=Pg_Pr0d#2024 dbname=designdb sslmode=disable"
	smtpHost          = "mail.internal.acmecorp.io"
	smtpPassword      = "SmtpR3lay#2024!"
)

func init() {
	users[1] = &User{1, "admin", "admin@acmecorp.io", "Adm1n_Pr0d!", "admin", true, 0}
	users[2] = &User{2, "jdoe", "jdoe@acmecorp.io", "JohnD_2024", "manager", true, 0}
	users[3] = &User{3, "asmith", "asmith@acmecorp.io", "alice_pass", "developer", true, 0}
	users[4] = &User{4, "bwilson", "bwilson@acmecorp.io", "B0b_W1ls0n", "analyst", false, 0}
}

func generateSessionToken(userID int) string {
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
	r.POST("/api/register", handleRegister)
	r.POST("/api/password-reset", handlePasswordReset)
	r.POST("/api/password-reset/confirm", handlePasswordResetConfirm)
	r.GET("/api/users/me", handleGetCurrentUser)
	r.PUT("/api/users/me/password", handleChangePassword)
	r.POST("/api/reports/generate", handleGenerateReport)
	r.GET("/api/config", handleGetConfig)
	r.GET("/api/debug/user/:id", handleDebugUser)
	r.GET("/api/health", handleHealthCheck)

	r.Run(":8087")
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
				c.JSON(http.StatusForbidden, gin.H{
					"error": fmt.Sprintf("Account '%s' is deactivated. Contact admin@acmecorp.io.", body.Username),
				})
				return
			}

			if user.Password == body.Password {
				user.FailedAttempts = 0
				token := generateSessionToken(uid)
				c.JSON(http.StatusOK, gin.H{"token": token, "user_id": uid, "role": user.Role})
				return
			}

			user.FailedAttempts++
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":    "Incorrect password",
				"attempts": user.FailedAttempts,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"error": fmt.Sprintf("No account found for username '%s'", body.Username),
	})
}

func handleRegister(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Username == "" || body.Email == "" || body.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "All fields required"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	for _, user := range users {
		if user.Username == body.Username {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Username '%s' is already taken", body.Username)})
			return
		}
		if user.Email == body.Email {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Email '%s' is already registered", body.Email)})
			return
		}
	}

	newID := 0
	for id := range users {
		if id > newID {
			newID = id
		}
	}
	newID++

	users[newID] = &User{newID, body.Username, body.Email, body.Password, "viewer", true, 0}
	c.JSON(http.StatusCreated, gin.H{"message": "User registered", "user_id": newID})
}

func handlePasswordReset(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email required"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	for uid, user := range users {
		if user.Email == body.Email {
			raw := fmt.Sprintf("%s%d", body.Email, time.Now().UnixNano())
			hash := md5.Sum([]byte(raw))
			resetToken := fmt.Sprintf("%x", hash[:8])
			passwordResetTkns[resetToken] = uid

			c.JSON(http.StatusOK, gin.H{
				"message":     "Password reset link sent",
				"token":       resetToken,
				"smtp_server": smtpHost,
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"error": fmt.Sprintf("No account associated with '%s'", body.Email),
	})
}

func handlePasswordResetConfirm(c *gin.Context) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token and new_password required"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	uid, ok := passwordResetTkns[body.Token]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired token"})
		return
	}

	user := users[uid]
	if user != nil {
		user.Password = body.NewPassword
		delete(passwordResetTkns, body.Token)
		c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
}

func handleGetCurrentUser(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	user := users[session.UserID]
	mu.RUnlock()

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id": user.ID, "username": user.Username,
		"email": user.Email, "role": user.Role,
	})
}

func handleChangePassword(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password required"})
		return
	}

	mu.Lock()
	user := users[session.UserID]
	if user == nil {
		mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	user.Password = body.NewPassword
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Password updated"})
}

func handleGenerateReport(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Type string `json:"type"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Report type required"})
		return
	}

	db, err := sql.Open("postgres", dbDSN)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database connection failed",
			"details": err.Error(),
			"dsn":     dbDSN,
		})
		return
	}
	defer db.Close()

	var query string
	switch body.Type {
	case "users":
		query = "SELECT * FROM users"
	case "audit":
		query = "SELECT * FROM audit_log"
	default:
		query = "SELECT * FROM " + body.Type
	}

	rows, err := db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Report generation failed",
			"details": err.Error(),
			"trace":   string(debug.Stack()),
			"dsn":     dbDSN,
		})
		return
	}
	defer rows.Close()

	c.JSON(http.StatusOK, gin.H{"report": "generated"})
}

func handleGetConfig(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	user := users[session.UserID]
	mu.RUnlock()

	if user == nil || user.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"database_dsn":  dbDSN,
		"smtp_host":     smtpHost,
		"smtp_password": smtpPassword,
		"session_count": len(sessions),
		"user_count":    len(users),
	})
}

func handleDebugUser(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	idStr := c.Param("id")
	uid, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	mu.RLock()
	user := users[uid]
	mu.RUnlock()

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func handleHealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "design-api"})
}
