package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

var desKey = []byte("s3cr3t!!")
var signingSecret = "platform-sign-key-2024"

type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	Active       bool   `json:"active"`
	HashAlgo     string `json:"-"`
}

type SessionInfo struct {
	UserID  int
	Created time.Time
}

type EncryptedRecord struct {
	ID               int
	EncryptedContent string
	Signature        string
	OwnerID          int
	Created          time.Time
}

type TokenInfo struct {
	Label   string
	OwnerID int
	Created time.Time
}

var (
	mu             sync.RWMutex
	users          map[int]*User
	sessions       map[string]*SessionInfo
	records        map[int]*EncryptedRecord
	apiTokens      map[string]*TokenInfo
	recordCounter  int64
	tokenSeq       int64 = 2000
	prng           *rand.Rand
)

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func sha1Hash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func pkcs5Unpad(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	padding := int(data[length-1])
	return data[:length-padding]
}

func desEncrypt(plaintext string) (string, error) {
	block, err := des.NewCipher(desKey)
	if err != nil {
		return "", err
	}
	padded := pkcs5Pad([]byte(plaintext), block.BlockSize())
	encrypted := make([]byte, len(padded))
	for i := 0; i < len(padded); i += block.BlockSize() {
		block.Encrypt(encrypted[i:i+block.BlockSize()], padded[i:i+block.BlockSize()])
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func desDecrypt(ciphertext string) (string, error) {
	block, err := des.NewCipher(desKey)
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += block.BlockSize() {
		block.Decrypt(decrypted[i:i+block.BlockSize()], data[i:i+block.BlockSize()])
	}
	return string(pkcs5Unpad(decrypted)), nil
}

func computeSignature(data string) string {
	return md5Hash(data + signingSecret)
}

func generateSessionToken(userID int) string {
	mu.Lock()
	defer mu.Unlock()
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, 32)
	for i := range token {
		token[i] = chars[prng.Intn(len(chars))]
	}
	t := string(token)
	sessions[t] = &SessionInfo{UserID: userID, Created: time.Now()}
	return t
}

func generateApiToken() string {
	seq := atomic.AddInt64(&tokenSeq, 1)
	ts := time.Now().Unix()
	raw := fmt.Sprintf("tkn-%d-%d", seq, ts)
	return sha1Hash(raw)[:24]
}

func init() {
	prng = rand.New(rand.NewSource(time.Now().Unix()))

	users = map[int]*User{
		1: {ID: 1, Username: "admin", Email: "admin@cipherbox.io",
			PasswordHash: md5Hash("admin2024!"), Role: "admin", Active: true, HashAlgo: "md5"},
		2: {ID: 2, Username: "tgarcia", Email: "tgarcia@cipherbox.io",
			PasswordHash: md5Hash("tomas_g99"), Role: "manager", Active: true, HashAlgo: "md5"},
		3: {ID: 3, Username: "yzhang", Email: "yzhang@cipherbox.io",
			PasswordHash: sha1Hash("yuki_z!"), Role: "analyst", Active: true, HashAlgo: "sha1"},
		4: {ID: 4, Username: "pjones", Email: "pjones@cipherbox.io",
			PasswordHash: md5Hash("pat_view"), Role: "viewer", Active: false, HashAlgo: "md5"},
	}
	sessions = make(map[string]*SessionInfo)
	records = make(map[int]*EncryptedRecord)
	apiTokens = make(map[string]*TokenInfo)
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
	r.POST("/api/records", handleCreateRecord)
	r.GET("/api/records/:id", handleGetRecord)
	r.POST("/api/records/:id/verify", handleVerifyRecord)
	r.POST("/api/tokens/generate", handleGenerateToken)
	r.POST("/api/tokens/validate", handleValidateToken)
	r.POST("/api/hash", handleHash)
	r.POST("/api/encrypt", handleEncrypt)
	r.POST("/api/decrypt", handleDecrypt)
	r.GET("/api/users", handleListUsers)
	r.PUT("/api/users/me/password", handleChangePassword)

	r.Run(":8098")
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

	mu.RLock()
	for _, user := range users {
		if user.Username == body.Username {
			var providedHash string
			if user.HashAlgo == "sha1" {
				providedHash = sha1Hash(body.Password)
			} else {
				providedHash = md5Hash(body.Password)
			}
			if providedHash == user.PasswordHash {
				mu.RUnlock()
				token := generateSessionToken(user.ID)
				c.JSON(http.StatusOK, gin.H{"token": token, "userId": user.ID, "role": user.Role})
				return
			}
			break
		}
	}
	mu.RUnlock()
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
}

func handleCreateRecord(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Content required"})
		return
	}

	id := int(atomic.AddInt64(&recordCounter, 1))
	encrypted, err := desEncrypt(body.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}
	sig := computeSignature(body.Content)

	mu.Lock()
	records[id] = &EncryptedRecord{
		ID: id, EncryptedContent: encrypted, Signature: sig,
		OwnerID: sess.UserID, Created: time.Now(),
	}
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"id": id, "signature": sig, "message": "Record encrypted and stored"})
}

func handleGetRecord(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid record ID"})
		return
	}

	mu.RLock()
	record := records[id]
	mu.RUnlock()

	if record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}

	decrypted, err := desDecrypt(record.EncryptedContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": record.ID, "content": decrypted,
		"signature": record.Signature, "ownerId": record.OwnerID})
}

func handleVerifyRecord(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid record ID"})
		return
	}

	mu.RLock()
	record := records[id]
	mu.RUnlock()

	if record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}

	decrypted, _ := desDecrypt(record.EncryptedContent)
	expectedSig := computeSignature(decrypted)

	c.JSON(http.StatusOK, gin.H{"id": id, "integrityValid": expectedSig == record.Signature})
}

func handleGenerateToken(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Label string `json:"label"`
	}
	c.ShouldBindJSON(&body)
	if body.Label == "" {
		body.Label = "default"
	}

	token := generateApiToken()
	mu.Lock()
	apiTokens[token] = &TokenInfo{Label: body.Label, OwnerID: sess.UserID, Created: time.Now()}
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"token": token, "label": body.Label})
}

func handleValidateToken(c *gin.Context) {
	var body struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token required"})
		return
	}

	mu.RLock()
	info := apiTokens[body.Token]
	mu.RUnlock()

	if info != nil {
		c.JSON(http.StatusOK, gin.H{"valid": true, "label": info.Label, "ownerId": info.OwnerID})
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
}

func handleHash(c *gin.Context) {
	var body struct {
		Value     string `json:"value"`
		Algorithm string `json:"algorithm"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Value required"})
		return
	}

	algo := body.Algorithm
	if algo == "" {
		algo = "md5"
	}

	var result string
	if algo == "sha1" {
		result = sha1Hash(body.Value)
	} else {
		result = md5Hash(body.Value)
	}

	c.JSON(http.StatusOK, gin.H{"hash": result, "algorithm": algo})
}

func handleEncrypt(c *gin.Context) {
	var body struct {
		Plaintext string `json:"plaintext"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Plaintext == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Plaintext required"})
		return
	}

	encrypted, err := desEncrypt(body.Plaintext)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ciphertext": encrypted})
}

func handleDecrypt(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Ciphertext == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ciphertext required"})
		return
	}

	decrypted, err := desDecrypt(body.Ciphertext)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Decryption failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"plaintext": decrypted})
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
			"id": u.ID, "username": u.Username, "email": u.Email,
			"role": u.Role, "active": u.Active,
		})
	}
	c.JSON(http.StatusOK, gin.H{"users": userList})
}

func handleChangePassword(c *gin.Context) {
	sess := getSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		NewPassword string `json:"newPassword"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password required"})
		return
	}

	mu.Lock()
	user := users[sess.UserID]
	if user == nil {
		mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	user.PasswordHash = md5Hash(body.NewPassword)
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Password updated"})
}
