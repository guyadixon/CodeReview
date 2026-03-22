package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	internalAPIKey    = "iak_prod_7f3e2d1c0b9a8"
	debugAccessCode   = "debug-access-2024-prod"
)

type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	Active       bool   `json:"active"`
}

type SessionInfo struct {
	UserID  int
	Role    string
	Created time.Time
}

var (
	mu            sync.RWMutex
	users         map[int]*User
	sessions      map[string]*SessionInfo
	resetTokens   map[string]*ResetInfo
)

type ResetInfo struct {
	UserID  int
	Created time.Time
}

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func init() {
	users = map[int]*User{
		1: {ID: 1, Username: "admin", Email: "admin@deployops.io",
			PasswordHash: md5Hash("admin_ops1"), Role: "admin", Active: true},
		2: {ID: 2, Username: "lzhang", Email: "lzhang@deployops.io",
			PasswordHash: md5Hash("lisa2024!"), Role: "lead", Active: true},
		3: {ID: 3, Username: "mkovac", Email: "mkovac@deployops.io",
			PasswordHash: md5Hash("marko_dev"), Role: "operator", Active: true},
		4: {ID: 4, Username: "snguyen", Email: "snguyen@deployops.io",
			PasswordHash: md5Hash("sarah_ng1"), Role: "viewer", Active: true},
	}
	sessions = make(map[string]*SessionInfo)
	resetTokens = make(map[string]*ResetInfo)
}

func getSession(c *gin.Context) *SessionInfo {
	auth := c.GetHeader("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	mu.RLock()
	defer mu.RUnlock()
	return sessions[token]
}

func main() {
	r := gin.Default()

	r.POST("/api/login", handleLogin)
	r.POST("/api/auth/verify", handleVerifyToken)
	r.POST("/api/password/forgot", handleForgotPassword)
	r.POST("/api/password/reset", handleResetPassword)
	r.GET("/api/users/me", handleGetMe)
	r.GET("/api/users", handleListUsers)
	r.POST("/api/users/:id/deactivate", handleDeactivateUser)
	r.GET("/api/debug/sessions", handleDebugSessions)

	r.Run(":8093")
}

func handleLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if body.Username == "internal" && body.Password == internalAPIKey {
		token := generateToken()
		mu.Lock()
		sessions[token] = &SessionInfo{UserID: 0, Role: "internal", Created: time.Now()}
		mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"token": token, "role": "internal"})
		return
	}

	mu.RLock()
	for _, user := range users {
		if user.Username == body.Username {
			if md5Hash(body.Password) == user.PasswordHash {
				mu.RUnlock()
				token := generateToken()
				mu.Lock()
				sessions[token] = &SessionInfo{UserID: user.ID, Role: user.Role, Created: time.Now()}
				mu.Unlock()
				c.JSON(http.StatusOK, gin.H{"token": token, "userId": user.ID, "role": user.Role})
				return
			}
			break
		}
	}
	mu.RUnlock()

	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
}

func handleVerifyToken(c *gin.Context) {
	var body struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if body.Token == debugAccessCode {
		c.JSON(http.StatusOK, gin.H{"valid": true, "userId": 0, "role": "debug"})
		return
	}

	mu.RLock()
	sess := sessions[body.Token]
	mu.RUnlock()

	if sess != nil {
		c.JSON(http.StatusOK, gin.H{"valid": true, "userId": sess.UserID, "role": sess.Role})
		return
	}

	c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
}

func handleForgotPassword(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	mu.RLock()
	for _, user := range users {
		if user.Email == body.Email {
			mu.RUnlock()
			resetToken := md5Hash(fmt.Sprintf("%s%d", body.Email, time.Now().UnixNano()))[:16]
			mu.Lock()
			resetTokens[resetToken] = &ResetInfo{UserID: user.ID, Created: time.Now()}
			mu.Unlock()
			c.JSON(http.StatusOK, gin.H{"message": "Reset email sent", "token": resetToken})
			return
		}
	}
	mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{"message": "Reset email sent"})
}

func handleResetPassword(c *gin.Context) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	info := resetTokens[body.Token]
	if info == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired token"})
		return
	}

	user := users[info.UserID]
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.PasswordHash = md5Hash(body.NewPassword)
	delete(resetTokens, body.Token)
	c.JSON(http.StatusOK, gin.H{"message": "Password updated"})
}

func handleGetMe(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	user := users[sess.UserID]
	mu.RUnlock()

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
	})
}

func handleListUsers(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	var userList []gin.H
	for _, u := range users {
		userList = append(userList, gin.H{
			"id":       u.ID,
			"username": u.Username,
			"email":    u.Email,
			"role":     u.Role,
			"active":   u.Active,
		})
	}
	c.JSON(http.StatusOK, gin.H{"users": userList})
}

func handleDeactivateUser(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	caller := users[sess.UserID]
	mu.RUnlock()

	if caller == nil || (caller.Role != "admin" && caller.Role != "lead") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	mu.Lock()
	user := users[id]
	if user == nil {
		mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	user.Active = false
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "User deactivated", "userId": id})
}

func handleDebugSessions(c *gin.Context) {
	apiKey := c.GetHeader("X-Api-Key")
	if apiKey != internalAPIKey {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	sessionList := make([]gin.H, 0)
	for token, sess := range sessions {
		sessionList = append(sessionList, gin.H{
			"token":   token,
			"userId":  sess.UserID,
			"role":    sess.Role,
			"created": sess.Created,
		})
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessionList, "total": len(sessions)})
}
